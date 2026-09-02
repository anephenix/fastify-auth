import { Auth } from "@anephenix/auth";

export const auth = new Auth({ passwordValidationRules: { minLength: 8 } });
