"use client";

import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";

import { geographicToVector3, greatCirclePoints } from "@/lib/globe-geometry";
import { markerSources, routeSources } from "@/lib/globe-data";
import { SEVERITY_META } from "@/lib/labels";
import type { EventLocation } from "@/types/api";

const EARTH_RADIUS = 1;
const MARKER_RADIUS = 1.012;

interface Props {
  events: EventLocation[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onUnavailable: (reason: string) => void;
}

interface AnimatedRoute {
  curve: THREE.CatmullRomCurve3;
  phase: number;
}

function disposeObject(root: THREE.Object3D) {
  root.traverse((object) => {
    if (object instanceof THREE.Mesh || object instanceof THREE.Line) {
      object.geometry.dispose();
      const materials = Array.isArray(object.material) ? object.material : [object.material];
      materials.forEach((material) => material.dispose());
    }
  });
}

export default function ThreatGlobe({ events, selectedId, onSelect, onUnavailable }: Props) {
  const hostRef = useRef<HTMLDivElement>(null);
  const controlsRef = useRef<OrbitControls | null>(null);
  const latestRef = useRef({ onSelect, onUnavailable });
  const eventsRef = useRef(events);
  const selectedIdRef = useRef(selectedId);
  const focusedIdRef = useRef<string | null>(null);
  const rebuildRef = useRef<((rows: EventLocation[], selected: string | null) => void) | null>(null);
  const focusRef = useRef<((eventId: string | null) => void) | null>(null);
  const [ready, setReady] = useState(false);
  const [hovered, setHovered] = useState<EventLocation | null>(null);

  useEffect(() => {
    latestRef.current = { onSelect, onUnavailable };
  }, [onSelect, onUnavailable]);

  useEffect(() => {
    eventsRef.current = events;
    selectedIdRef.current = selectedId;
  }, [events, selectedId]);

  useEffect(() => {
    rebuildRef.current?.(events, selectedId);
  }, [events, selectedId]);

  useEffect(() => {
    if (focusedIdRef.current === selectedId) return;
    focusedIdRef.current = selectedId;
    focusRef.current?.(selectedId);
  }, [events, selectedId]);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let disposed = false;
    let frame = 0;
    let dayTexture: THREE.Texture | undefined;
    let nightTexture: THREE.Texture | undefined;
    let markerMesh: THREE.InstancedMesh | undefined;
    let surfaceMesh: THREE.Mesh | undefined;
    let eventGroup: THREE.Group | undefined;
    let tracerMesh: THREE.InstancedMesh | undefined;
    let markerEventIds: string[] = [];
    let routes: AnimatedRoute[] = [];
    let resizeObserver: ResizeObserver | undefined;
    let pointerStart: { x: number; y: number } | undefined;

    const fail = (reason: string) => {
      if (disposed) return;
      setReady(false);
      latestRef.current.onUnavailable(reason);
    };

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: false, antialias: true, powerPreference: "low-power" });
    } catch {
      fail("WebGL could not be initialized on this device.");
      return;
    }

    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.6));
    renderer.setClearColor(0x030712, 1);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.domElement.className = "block h-full w-full touch-none outline-none";
    renderer.domElement.setAttribute("aria-hidden", "true");
    host.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    scene.background = new THREE.Color(0x030712);
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
    camera.position.set(0, 0.08, 3.35);

    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.06;
    controls.enablePan = false;
    controls.minDistance = 1.45;
    controls.maxDistance = 5;
    controls.autoRotate = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    controls.autoRotateSpeed = 0.2;
    controlsRef.current = controls;

    scene.add(new THREE.AmbientLight(0x9bb6d4, 0.12));
    const sunDirection = new THREE.Vector3(-4, 1.5, 4).normalize();
    const sunlight = new THREE.DirectionalLight(0xdbeafe, 2.2);
    sunlight.position.copy(sunDirection).multiplyScalar(5);
    scene.add(sunlight);

    const earthGroup = new THREE.Group();
    scene.add(earthGroup);
    let focusTarget: THREE.Quaternion | null = null;
    const focusEarth = (eventId: string | null) => {
      if (!eventId) {
        focusTarget = null;
        controls.autoRotate = !window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        return;
      }
      const source = markerSources(eventsRef.current).find((item) => item.eventId === eventId);
      const event = eventsRef.current.find((item) => item.id === eventId);
      const point = source?.point ?? (event?.latitude != null && event.longitude != null
        ? { latitude: event.latitude, longitude: event.longitude }
        : null);
      if (!point) return;
      const surfaceDirection = geographicToVector3(point).normalize();
      focusTarget = new THREE.Quaternion().setFromUnitVectors(surfaceDirection, new THREE.Vector3(0, 0, 1));
      controls.autoRotate = false;
    };
    focusRef.current = focusEarth;

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(EARTH_RADIUS * 1.055, 64, 48),
      new THREE.ShaderMaterial({
        vertexShader: `
          varying vec3 vNormal;
          varying vec3 vViewPosition;
          void main() {
            vec4 mvPosition = modelViewMatrix * vec4(position, 1.0);
            vNormal = normalize(normalMatrix * normal);
            vViewPosition = -mvPosition.xyz;
            gl_Position = projectionMatrix * mvPosition;
          }
        `,
        fragmentShader: `
          varying vec3 vNormal;
          varying vec3 vViewPosition;
          void main() {
            float rim = 1.0 - max(dot(normalize(vNormal), normalize(vViewPosition)), 0.0);
            float glow = pow(rim, 3.2) * 0.62;
            gl_FragColor = vec4(0.16, 0.56, 0.96, glow);
            #include <tonemapping_fragment>
            #include <colorspace_fragment>
          }
        `,
        side: THREE.BackSide,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    earthGroup.add(atmosphere);

    const loader = new THREE.TextureLoader();
    Promise.all([
      loader.loadAsync("/textures/earth-day.jpg"),
      loader.loadAsync("/textures/earth-night.jpg"),
    ])
      .then(([day, night]) => {
        if (disposed) {
          day.dispose();
          night.dispose();
          return;
        }
        dayTexture = day;
        nightTexture = night;
        day.colorSpace = THREE.SRGBColorSpace;
        night.colorSpace = THREE.SRGBColorSpace;
        day.anisotropy = renderer.capabilities.getMaxAnisotropy();
        night.anisotropy = day.anisotropy;

        surfaceMesh = new THREE.Mesh(
          new THREE.SphereGeometry(EARTH_RADIUS, 96, 64),
          new THREE.MeshStandardMaterial({ map: day, roughness: 1, metalness: 0 }),
        );
        earthGroup.add(surfaceMesh);

        const cityLights = new THREE.Mesh(
          new THREE.SphereGeometry(EARTH_RADIUS * 1.0015, 96, 64),
          new THREE.ShaderMaterial({
            uniforms: {
              lightsMap: { value: night },
              sunDirection: { value: sunDirection },
            },
            vertexShader: `
              varying vec2 vUv;
              varying vec3 vWorldNormal;
              void main() {
                vUv = uv;
                vWorldNormal = normalize(mat3(modelMatrix) * normal);
                gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
              }
            `,
            fragmentShader: `
              uniform sampler2D lightsMap;
              uniform vec3 sunDirection;
              varying vec2 vUv;
              varying vec3 vWorldNormal;
              void main() {
                vec3 lights = texture2D(lightsMap, vUv).rgb;
                float luminance = max(max(lights.r, lights.g), lights.b);
                float cityMask = smoothstep(0.06, 0.45, luminance);
                float nightSide = 1.0 - smoothstep(-0.12, 0.08, dot(normalize(vWorldNormal), normalize(sunDirection)));
                float alpha = cityMask * nightSide * 0.95;
                gl_FragColor = vec4(lights * 1.2, alpha);
                #include <tonemapping_fragment>
                #include <colorspace_fragment>
              }
            `,
            transparent: true,
            depthWrite: false,
            blending: THREE.AdditiveBlending,
          }),
        );
        cityLights.renderOrder = 1;
        earthGroup.add(cityLights);

        const updateEventLayers = (rows: EventLocation[], currentSelectedId: string | null) => {
          if (eventGroup) {
            earthGroup.remove(eventGroup);
            disposeObject(eventGroup);
          }
          markerMesh = undefined;
          tracerMesh = undefined;
          markerEventIds = [];
          eventGroup = new THREE.Group();
          earthGroup.add(eventGroup);

          const sources = markerSources(rows);
          if (sources.length > 0) {
            markerMesh = new THREE.InstancedMesh(
              new THREE.SphereGeometry(0.018, 12, 8),
              new THREE.MeshBasicMaterial({ vertexColors: true, toneMapped: false }),
              sources.length,
            );
            const matrix = new THREE.Matrix4();
            const scale = new THREE.Vector3();
            const color = new THREE.Color();
            markerEventIds = sources.map((source, index) => {
              const position = geographicToVector3(source.point, MARKER_RADIUS);
              const selected = source.eventId === currentSelectedId;
              const size = selected ? 1.65 : source.severity === "critical" ? 1.35 : 1;
              scale.setScalar(size);
              matrix.compose(position, new THREE.Quaternion(), scale);
              markerMesh?.setMatrixAt(index, matrix);
              color.set(SEVERITY_META[source.severity].hex);
              markerMesh?.setColorAt(index, color);
              return source.eventId;
            });
            markerMesh.instanceMatrix.needsUpdate = true;
            if (markerMesh.instanceColor) markerMesh.instanceColor.needsUpdate = true;
            markerMesh.computeBoundingSphere();
            markerMesh.renderOrder = 3;
            eventGroup.add(markerMesh);
          }

          const routeRows = routeSources(rows);
          routes = routeRows.map((route, index) => {
            const points = greatCirclePoints(route.origin, route.destination, 48, EARTH_RADIUS);
            const curve = new THREE.CatmullRomCurve3(points, false, "centripetal");
            const line = new THREE.Line(
              new THREE.BufferGeometry().setFromPoints(points),
              new THREE.LineBasicMaterial({
                color: SEVERITY_META[route.severity].hex,
                transparent: true,
                opacity: 0.7,
                depthWrite: false,
                toneMapped: false,
              }),
            );
            line.renderOrder = 2;
            line.userData.eventId = route.eventId;
            eventGroup?.add(line);
            return { curve, phase: (index * 0.61803398875) % 1 };
          });

          if (routes.length > 0) {
            tracerMesh = new THREE.InstancedMesh(
              new THREE.SphereGeometry(0.012, 8, 6),
              new THREE.MeshBasicMaterial({ vertexColors: true, toneMapped: false }),
              routes.length,
            );
            const matrix = new THREE.Matrix4();
            const color = new THREE.Color();
            const scale = new THREE.Vector3(1, 1, 1);
            routes.forEach((route, index) => {
              color.set(SEVERITY_META[routeRows[index].severity].hex);
              tracerMesh?.setColorAt(index, color);
              matrix.compose(
                route.curve.getPoint((route.phase + 0.5) % 1),
                new THREE.Quaternion(),
                scale,
              );
              tracerMesh?.setMatrixAt(index, matrix);
            });
            if (tracerMesh.instanceColor) tracerMesh.instanceColor.needsUpdate = true;
            tracerMesh.instanceMatrix.needsUpdate = true;
            tracerMesh.renderOrder = 4;
            eventGroup.add(tracerMesh);
          }
        };
        rebuildRef.current = updateEventLayers;
        updateEventLayers(eventsRef.current, selectedIdRef.current);

        const handleResize = () => {
          if (!host.clientWidth || !host.clientHeight) return;
          camera.aspect = host.clientWidth / host.clientHeight;
          camera.updateProjectionMatrix();
          renderer.setSize(host.clientWidth, host.clientHeight, false);
        };
        resizeObserver = new ResizeObserver(handleResize);
        resizeObserver.observe(host);
        handleResize();

        const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        const clock = new THREE.Clock();
        const animate = () => {
          if (disposed) return;
          frame = window.requestAnimationFrame(animate);
          controls.update();
          if (focusTarget) {
            earthGroup.quaternion.slerp(focusTarget, 0.055);
            if (earthGroup.quaternion.angleTo(focusTarget) < 0.002) {
              earthGroup.quaternion.copy(focusTarget);
              focusTarget = null;
            }
          }
          if (tracerMesh && !reducedMotion) {
            const elapsed = clock.getElapsedTime() * 0.08;
            const matrix = new THREE.Matrix4();
            const scale = new THREE.Vector3(1, 1, 1);
            routes.forEach((route, index) => {
              const progress = (elapsed + route.phase) % 1;
              matrix.compose(route.curve.getPoint(progress), new THREE.Quaternion(), scale);
              tracerMesh?.setMatrixAt(index, matrix);
            });
            tracerMesh.instanceMatrix.needsUpdate = true;
          }
          renderer.render(scene, camera);
        };
        animate();
        setReady(true);
      })
      .catch(() => fail("The Earth texture assets could not be loaded."));

    const pickMarker = (clientX: number, clientY: number): string | null => {
      if (!markerMesh) return null;
      const bounds = renderer.domElement.getBoundingClientRect();
      const pointer = new THREE.Vector2(
        ((clientX - bounds.left) / bounds.width) * 2 - 1,
        -((clientY - bounds.top) / bounds.height) * 2 + 1,
      );
      const raycaster = new THREE.Raycaster();
      raycaster.setFromCamera(pointer, camera);
      const intersections = raycaster.intersectObjects([surfaceMesh, markerMesh].filter(Boolean) as THREE.Object3D[]);
      const first = intersections[0];
      if (first?.object !== markerMesh || first.instanceId === undefined) return null;
      return markerEventIds[first.instanceId] ?? null;
    };

    const handlePointerDown = (event: PointerEvent) => {
      pointerStart = { x: event.clientX, y: event.clientY };
    };
    const handlePointerUp = (event: PointerEvent) => {
      if (!pointerStart) return;
      const moved = Math.hypot(event.clientX - pointerStart.x, event.clientY - pointerStart.y);
      pointerStart = undefined;
      if (moved > 5) return;
      const id = pickMarker(event.clientX, event.clientY);
      if (id) latestRef.current.onSelect(id);
    };
    const handlePointerMove = (event: PointerEvent) => {
      const id = pickMarker(event.clientX, event.clientY);
      const eventUnderPointer = id ? eventsRef.current.find((item) => item.id === id) ?? null : null;
      setHovered((current) => (current?.id === eventUnderPointer?.id ? current : eventUnderPointer));
      renderer.domElement.style.cursor = id ? "pointer" : "grab";
    };
    const handleContextLost = (event: Event) => {
      event.preventDefault();
      fail("WebGL became unavailable. Showing the 2D map instead.");
    };

    renderer.domElement.addEventListener("pointerdown", handlePointerDown);
    renderer.domElement.addEventListener("pointerup", handlePointerUp);
    renderer.domElement.addEventListener("pointermove", handlePointerMove);
    renderer.domElement.addEventListener("webglcontextlost", handleContextLost);

    return () => {
      disposed = true;
      window.cancelAnimationFrame(frame);
      resizeObserver?.disconnect();
      renderer.domElement.removeEventListener("pointerdown", handlePointerDown);
      renderer.domElement.removeEventListener("pointerup", handlePointerUp);
      renderer.domElement.removeEventListener("pointermove", handlePointerMove);
      renderer.domElement.removeEventListener("webglcontextlost", handleContextLost);
      controls.dispose();
      controlsRef.current = null;
      rebuildRef.current = null;
      focusRef.current = null;
      focusedIdRef.current = null;
      if (eventGroup) disposeObject(eventGroup);
      if (earthGroup) disposeObject(earthGroup);
      dayTexture?.dispose();
      nightTexture?.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  return (
    <div className="absolute inset-0" aria-label="Interactive three-dimensional Earth" role="region">
      <div ref={hostRef} className="absolute inset-0" />
      {!ready && (
        <div className="pointer-events-none absolute inset-0 grid place-items-center" role="status">
          <span className="rounded-md border border-slate-700 bg-cyber-black/80 px-3 py-2 text-xs text-slate-300">
            Loading Earth textures…
          </span>
        </div>
      )}
      {hovered && (
        <div className="pointer-events-none absolute bottom-16 left-4 max-w-[min(22rem,calc(100%-2rem))] rounded-md border border-slate-700 bg-cyber-black/95 px-3 py-2 shadow-xl">
          <p className="text-xs font-semibold text-white">{hovered.title}</p>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-wide text-slate-400">
            {SEVERITY_META[hovered.severity].label} · {hovered.threat_type.replaceAll("_", " ")}
          </p>
        </div>
      )}
      <div className="absolute right-3 top-3 flex flex-col gap-1" aria-label="Globe controls">
        <button
          type="button"
          className="btn-secondary h-9 w-9 !p-0"
          aria-label="Zoom in on Earth"
          onClick={() => {
            const controls = controlsRef.current;
            if (!controls) return;
            controls.object.position.multiplyScalar(0.8);
            controls.update();
          }}
        >
          +
        </button>
        <button
          type="button"
          className="btn-secondary h-9 w-9 !p-0"
          aria-label="Zoom out from Earth"
          onClick={() => {
            const controls = controlsRef.current;
            if (!controls) return;
            controls.object.position.multiplyScalar(1.25);
            controls.update();
          }}
        >
          −
        </button>
        <button
          type="button"
          className="btn-secondary h-9 w-9 !p-0 text-xs"
          aria-label="Reset Earth view"
          onClick={() => {
            const controls = controlsRef.current;
            if (!controls) return;
            controls.object.position.set(0, 0.08, 3.35);
            controls.target.set(0, 0, 0);
            controls.update();
          }}
        >
          ↺
        </button>
      </div>
      <p className="absolute bottom-3 left-3 text-[10px] text-slate-500">
        Earth textures: NASA Blue Marble / Black Marble
      </p>
    </div>
  );
}
