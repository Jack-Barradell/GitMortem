import { api } from "@/api/client";
import type { components } from "@/api/schema";

type Schemas = components["schemas"];
type Choice = Schemas["ChoicesOut"]["items"][number];
export type Dimension = Schemas["ChoicesIn"]["dimension"];
export type PickerValue = number | string;

export interface PickerOption {
  value: PickerValue;
  label: string;
  count: string;
}

export interface PickerSource {
  ask: (text: string) => Promise<PickerOption[]>;
  name?: (values: PickerValue[]) => Promise<PickerOption[]>;
  fallback: (value: PickerValue) => string;
}

export const MAX_PICKER_TEXT = 256;
export const NO_ORG_VALUE = "\u0000";
const NO_ORG = "No org";

function orgValue(value: PickerValue): PickerValue {
  return value === "" ? NO_ORG_VALUE : value;
}

function counted(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

function ofChoice(choice: Choice): PickerOption {
  return {
    value: orgValue(choice.value),
    label: choice.label,
    count: counted(choice.unique, "secret", "secrets"),
  };
}

async function choices(dimension: Dimension, text: string, ids: number[]): Promise<Choice[]> {
  const found = await api<Schemas["ChoicesOut"]>("/api/triage/choices", {
    method: "POST",
    body: { dimension, text: text.slice(0, MAX_PICKER_TEXT), ids },
  });
  return found.items;
}

export function triageChoices(dimension: Dimension): PickerSource {
  return {
    ask: async (text) => (await choices(dimension, text, [])).map(ofChoice),
    name:
      dimension === "repository"
        ? async (values) => (await choices(dimension, "", values as number[])).map(ofChoice)
        : undefined,
    fallback: (value) => (value === NO_ORG_VALUE ? NO_ORG : String(value)),
  };
}

export function rootOrgs(root: number): PickerSource {
  return {
    ask: async (text) => {
      const found = await api<Schemas["RepositoryOrgsOut"]>("/api/repositories/orgs", {
        method: "POST",
        body: { root, text: text.slice(0, MAX_PICKER_TEXT) },
      });
      return found.items.map((org) => ({
        value: orgValue(org.value),
        label: org.label,
        count: counted(org.repositories, "repository", "repositories"),
      }));
    },
    fallback: (value) => (value === NO_ORG_VALUE ? NO_ORG : String(value)),
  };
}
