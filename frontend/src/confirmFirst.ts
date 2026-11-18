import { reactive } from "vue";
import type { ConfirmationOptions } from "primevue/confirmationoptions";

export const ACCEPT_DELAY_MS = 600;

type Confirmer = { require: (options: ConfirmationOptions) => void };

export type FirstAsk = {
  header: string;
  message: string;
  acceptLabel: string;
  danger?: boolean;
  accept: () => unknown;
  reject?: () => void;
  hidden?: () => void;
};

export function confirmFirst(confirm: Confirmer, ask: FirstAsk): void {
  const acceptProps = reactive({
    severity: ask.danger ? "danger" : "primary",
    disabled: true,
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  confirm.require({
    header: ask.header,
    message: ask.message,
    icon: "pi pi-exclamation-triangle",
    acceptLabel: ask.acceptLabel,
    rejectLabel: "Cancel",
    defaultFocus: "reject",
    acceptProps,
    rejectProps: { severity: "secondary", variant: "outlined" },
    onShow: () => {
      timer = setTimeout(() => {
        acceptProps.disabled = false;
      }, ACCEPT_DELAY_MS);
    },
    onHide: () => {
      clearTimeout(timer);
      ask.hidden?.();
    },
    accept: () => {
      if (!acceptProps.disabled) void ask.accept();
    },
    reject: () => ask.reject?.(),
  });
}
