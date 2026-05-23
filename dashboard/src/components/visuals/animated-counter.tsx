"use client";

import { useEffect, useState } from "react";
import { motion, useMotionValue, useSpring, useTransform } from "framer-motion";

// Animates a number from its previous value to the next, with a
// smoothed spring. The animation is meaningful: a counter that
// re-renders without animation just changes; one that animates
// conveys "this metric was computed and is now showing you the
// result." Used on every page's headline stats.

interface AnimatedCounterProps {
  value: number;
  format?: (n: number) => string;
  className?: string;
}

export function AnimatedCounter({
  value,
  format = (n) => n.toLocaleString("en-US"),
  className,
}: AnimatedCounterProps) {
  const motionValue = useMotionValue(0);
  const spring = useSpring(motionValue, {
    stiffness: 90,
    damping: 22,
    mass: 0.6,
  });
  const rounded = useTransform(spring, (latest) => Math.round(latest));
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    motionValue.set(value);
  }, [value, motionValue]);

  useEffect(() => {
    const unsub = rounded.on("change", setDisplay);
    return unsub;
  }, [rounded]);

  return (
    <motion.span
      className={className}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.3 }}
    >
      {format(display)}
    </motion.span>
  );
}
