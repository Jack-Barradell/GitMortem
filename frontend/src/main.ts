import { definePreset } from "@primeuix/themes";
import Aura from "@primeuix/themes/aura";
import "primeicons/primeicons.css";
import { createPinia } from "pinia";
import PrimeVue from "primevue/config";
import ConfirmationService from "primevue/confirmationservice";
import ToastService from "primevue/toastservice";
import { createApp } from "vue";
import App from "./App.vue";
import { createAppRouter, installUnauthorizedRedirect } from "./router";
import { installSessionWatch } from "./sessionWatch";
import "./styles.css";
import { DARK_SURFACE, LIGHT_SURFACE } from "./palette";
import { installTheme } from "./theme";

const GitMortem = definePreset(Aura, {
  semantic: {
    primary: {
      50: "{teal.50}",
      100: "{teal.100}",
      200: "{teal.200}",
      300: "{teal.300}",
      400: "{teal.400}",
      500: "{teal.500}",
      600: "{teal.600}",
      700: "{teal.700}",
      800: "{teal.800}",
      900: "{teal.900}",
      950: "{teal.950}",
    },
    colorScheme: {
      light: { surface: LIGHT_SURFACE },
      dark: { surface: DARK_SURFACE },
    },
  },
});

const nonce = document.querySelector<HTMLMetaElement>('meta[name="csp-nonce"]')?.content;

installTheme();

const pinia = createPinia();
const router = createAppRouter();
installUnauthorizedRedirect(router);
installSessionWatch(router);

createApp(App)
  .use(pinia)
  .use(router)
  .use(PrimeVue, {
    csp: { nonce },
    theme: {
      preset: GitMortem,
      options: {
        darkModeSelector: ".dark",
        cssLayer: { name: "primevue", order: "theme, base, primevue" },
      },
    },
  })
  .use(ToastService)
  .use(ConfirmationService)
  .mount("#app");
