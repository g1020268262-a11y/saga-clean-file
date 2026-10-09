(* Derived scenario fragment; not a standalone model or new verifier result.
   evaluation_sha256: 40888f0bb40808888091783a8f63adb9fb9a6615a04a13efdd9d31c4a8d010a5
   Initiator -> aid_B; symbolic receiver -> aid_A; policy -> BuggyPolicy.
   Replace the two initial scenario inserts in a future derived model. *)
insert ScenarioSpecDeny(BuggyPolicy, aid_B);
insert ScenarioImplAllow(BuggyPolicy, aid_B);
