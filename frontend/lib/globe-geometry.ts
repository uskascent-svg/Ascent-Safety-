import * as THREE from "three";

export interface GeoPoint {
  latitude: number;
  longitude: number;
}

/** Convert geographic coordinates to a point on the sphere using the equirectangular UV layout. */
export function geographicToVector3(point: GeoPoint, radius = 1): THREE.Vector3 {
  if (
    !Number.isFinite(point.latitude) ||
    !Number.isFinite(point.longitude) ||
    point.latitude < -90 ||
    point.latitude > 90 ||
    point.longitude < -180 ||
    point.longitude > 180 ||
    !Number.isFinite(radius) ||
    radius <= 0
  ) {
    throw new RangeError("Coordinates and sphere radius must be within geographic bounds");
  }

  const lat = THREE.MathUtils.degToRad(point.latitude);
  const lon = THREE.MathUtils.degToRad(point.longitude);
  const horizontal = Math.cos(lat) * radius;
  return new THREE.Vector3(horizontal * Math.cos(lon), Math.sin(lat) * radius, -horizontal * Math.sin(lon));
}

/** Build points along the shortest great-circle route, raised above the globe surface. */
export function greatCirclePoints(
  origin: GeoPoint,
  destination: GeoPoint,
  segments = 64,
  radius = 1,
): THREE.Vector3[] {
  if (!Number.isInteger(segments) || segments < 2) {
    throw new RangeError("A great-circle route needs at least two segments");
  }

  const start = geographicToVector3(origin).normalize();
  const end = geographicToVector3(destination).normalize();
  const angle = start.angleTo(end);
  const sine = Math.sin(angle);
  const points: THREE.Vector3[] = [];
  const height = Math.max(0.035, Math.sin(angle / 2) * 0.22);
  let antipodalPerpendicular: THREE.Vector3 | undefined;

  if (Math.abs(sine) < 1e-6 && angle > 1e-6) {
    const axis = Math.abs(start.x) < 0.8 ? new THREE.Vector3(1, 0, 0) : new THREE.Vector3(0, 1, 0);
    antipodalPerpendicular = axis.addScaledVector(start, -axis.dot(start)).normalize();
  }

  for (let index = 0; index <= segments; index += 1) {
    const progress = index / segments;
    let direction: THREE.Vector3;

    if (angle < 1e-6) {
      direction = start.clone();
    } else if (antipodalPerpendicular) {
      direction = start
        .clone()
        .multiplyScalar(Math.cos(Math.PI * progress))
        .addScaledVector(antipodalPerpendicular, Math.sin(Math.PI * progress));
    } else {
      direction = start
        .clone()
        .multiplyScalar(Math.sin((1 - progress) * angle) / sine)
        .addScaledVector(end, Math.sin(progress * angle) / sine);
    }

    const arcHeight = Math.sin(Math.PI * progress) * height;
    points.push(direction.normalize().multiplyScalar(radius * (1 + arcHeight)));
  }

  return points;
}
