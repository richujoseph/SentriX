import { useEffect, useState } from "react";

// Minimal hash router: "#/incidents/7" -> "/incidents/7". Avoids a routing
// dependency for an app with two views.
function currentPath() {
  return window.location.hash.replace(/^#/, "") || "/";
}

export function useHashPath() {
  const [path, setPath] = useState(currentPath);
  useEffect(() => {
    const onChange = () => {
      setPath(currentPath());
      window.scrollTo(0, 0);
    };
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  return path;
}

export const incidentHref = (id) => `#/incidents/${id}`;
