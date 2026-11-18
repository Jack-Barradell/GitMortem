import { useToast } from "primevue/usetoast";

export function useSay() {
  const toast = useToast();
  return (severity: "success" | "warn" | "error", summary: string, detail?: string): void => {
    toast.add({ severity, summary, detail, life: 6000 });
  };
}
