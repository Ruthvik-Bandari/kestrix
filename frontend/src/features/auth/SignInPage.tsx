// SPDX-FileCopyrightText: 2026 Ruthvik Bandari
// SPDX-License-Identifier: Apache-2.0
import { useSearchParams } from "react-router";
import { dashboardPath, safeNext } from "../../app/paths";
import { BrandMark } from "../../components/BrandMark";
import { PublicShell } from "../../components/PublicShell";
import { useTitle } from "../../lib/useTitle";
import { AuthCard } from "./AuthCard";

export default function SignInPage() {
  useTitle("Sign in");
  const [params] = useSearchParams();
  const next = safeNext(params.get("next")) ?? dashboardPath();

  return (
    <PublicShell action={false}>
      <BrandMark size={40} />
      <h1 className="display mt-5 text-[clamp(2rem,6vw,2.75rem)]">Sign in to Kestrix</h1>
      <AuthCard next={next} className="mt-7" />
    </PublicShell>
  );
}
