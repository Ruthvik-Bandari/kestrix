// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef } from "react";
import { prefersReducedMotion } from "./motion";

/**
 * Scroll reveal. Marks the element `data-reveal="pending"` until it enters the viewport,
 * then `"shown"`; index.css animates the change only when motion is allowed. Without
 * IntersectionObserver or with reduced motion the element is shown at once, so content is
 * never left hidden.
 */
export function useReveal<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    if (prefersReducedMotion() || typeof IntersectionObserver === "undefined") {
      node.dataset.reveal = "shown";
      return;
    }
    node.dataset.reveal = "pending";
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          node.dataset.reveal = "shown";
          observer.disconnect();
        }
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.08 },
    );
    observer.observe(node);
    return () => {
      observer.disconnect();
    };
  }, []);
  return ref;
}
