import Reveal from "reveal.js";
import Notes from "reveal.js/plugin/notes";
import "reveal.js/reveal.css";
import "./style.css";

const deck = new Reveal({
  width: 1600,
  height: 900,
  margin: 0,
  center: false,
  controls: false,
  controlsTutorial: false,
  progress: true,
  hash: true,
  history: true,
  hideInactiveCursor: true,
  hideCursorTime: 0,
  transition: "fade",
  backgroundTransition: "fade",
  plugins: [Notes],
});

const disableTabNavigation = () => {
  document
    .querySelectorAll(".reveal a, .reveal button, .reveal input, .reveal select, .reveal textarea, .reveal [tabindex]")
    .forEach((element) => element.setAttribute("tabindex", "-1"));
};

document.addEventListener("keydown", (event) => {
  if (event.key === "Tab") event.preventDefault();
});

deck.on("ready", disableTabNavigation);

deck.on("fragmentshown", ({ fragment }) => {
  if (fragment.classList.contains("ticket-open-trigger")) {
    const slide = fragment.closest("section");
    slide.classList.add("ticket-open-clicking");
    window.setTimeout(() => deck.next(), 320);
  }

  if (fragment.classList.contains("ticket-close-trigger")) {
    fragment.closest("section").classList.add("ticket-closed");
  }
});

deck.on("fragmenthidden", ({ fragment }) => {
  if (fragment.classList.contains("ticket-open-trigger")) {
    fragment.closest("section").classList.remove("ticket-open-clicking");
  }

  if (fragment.classList.contains("ticket-close-trigger")) {
    fragment.closest("section").classList.remove("ticket-closed");
  }
});

deck.initialize();
