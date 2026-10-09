"""Build three independent Provider/receiver authorization control models.

The existing Stage 2 allow model is an immutable historical input. This script
only changes the authorization-control abstraction and its queries; it does not
alter the cryptographic protocol or model the production policy matcher.
"""

from pathlib import Path


PROVERIF = Path(__file__).resolve().parent / "proverif"
SOURCE = PROVERIF / "agent_communication_authz_chat_allow.pv"
SCENARIOS = {
    "p_allow_r_allow": (True, True),
    "p_deny_r_allow": (False, True),
    "p_allow_r_deny": (True, False),
}


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f"Expected one occurrence, found {count}: {old[:72]!r}")
    return text.replace(old, new)


def build(source: str, provider_allow: bool, receiver_allow: bool) -> str:
    model = replace_once(
        source,
        "  SAGA FULL AGENT COMMUNICATION PROTOCOL; CHECKING SECRECY AND AUTHENTICATION",
        "  SAGA AGENT COMMUNICATION: INDEPENDENT PROVIDER AND RECEIVER GATES",
    )
    begin = model.index("(* AUTHZ-BEGIN *)")
    end = model.index("event start().", begin)
    model = model[:begin] + """(* The Stage 1 Accept event means B received and verified A's token. *)
event TokenIssue(bitstring, bitstring, bitstring).
event Accept(bitstring, bitstring, bitstring).

(* Scenario events are assumptions, not results of evaluating a rulebook.
   ProviderReleased abstracts the causal handoff of Provider authorization
   to PeerA; the channel messages alone do not establish this handoff. *)
event ScenarioProviderAllow(bitstring, bitstring).
event ScenarioProviderDeny(bitstring, bitstring).
event ScenarioReceiverAllow(bitstring, bitstring).
event ScenarioReceiverDeny(bitstring, bitstring).
event ProviderRelease(bitstring, bitstring).
event TokenReceive(bitstring, bitstring, bitstring).
event ChatSend(bitstring, bitstring, bitstring, bitstring).
event ChatAccept(bitstring, bitstring, bitstring, bitstring).
table ProviderAuthorized(bitstring, bitstring).
table ReceiverAuthorized(bitstring, bitstring).
table ProviderReleased(bitstring, bitstring).
table ActiveToken(bitstring, bitstring, bitstring, pkey).

""" + model[end:]
    # Two historical guards are deliberately replaced at distinct sites.
    if model.count("get Authorized(=aid_A, =aid_B) in") != 2:
        raise ValueError("Expected separate PeerA and Provider guard sites")
    model = model.replace(
        "get Authorized(=aid_A, =aid_B) in",
        "get ProviderReleased(=aid_A, =aid_B) in\n"
        "  get ReceiverAuthorized(=aid_A, =aid_B) in",
        1,
    )
    model = replace_once(
        model,
        "get Authorized(=aid_A, =aid_B) in\n  out(prov_b,",
        "get ProviderAuthorized(=aid_A, =aid_B) in\n  out(prov_b,",
    )
    model = replace_once(
        model,
        "out(prov_b, (Cert_A, Cert_B, aid_A, OTK1_A_sig, OTK1_A, sigma_A_sig, PAC_A, ED_A));",
        "out(prov_b, (Cert_A, Cert_B, aid_A, OTK1_A_sig, OTK1_A, sigma_A_sig, PAC_A, ED_A));\n"
        "  event ProviderRelease(aid_A, aid_B);\n"
        "  insert ProviderReleased(aid_A, aid_B);",
    )
    query_begin = model.index("(* Stage 2 queries only;")
    history_begin = model.index("(*\n\n$ time proverif", query_begin)
    process_begin = model.index("process \n", history_begin)
    model = model[:query_begin] + """(* Each gate has its own reachability observation. The private tls_chat
   channel abstracts authenticated transport; it is not a TLS proof. *)
query event(ProviderRelease(aid_A, aid_B)).
query tok: bitstring;
    event(TokenIssue(aid_A, aid_B, tok)).
query tok: bitstring, msg: bitstring;
    event(ChatAccept(aid_A, aid_B, tok, msg)).
query receiver: bitstring, sender: bitstring, tok: bitstring, msg: bitstring;
    event(ChatAccept(receiver, sender, tok, msg))
    ==> event(TokenIssue(receiver, sender, tok)).
query receiver: bitstring, sender: bitstring, tok: bitstring, msg: bitstring;
    event(ChatAccept(receiver, sender, tok, msg))
    ==> event(ChatSend(receiver, sender, tok, msg)).

""" + model[process_begin:]
    scenario_begin = model.index("(* AUTHZ-BEGIN *)", model.index("process \n"))
    scenario_end = model.index("(* AUTHZ-END *)", scenario_begin) + len("(* AUTHZ-END *)")
    scenario = (
        "  (* Independent scenario assumptions: no rulebook evaluation. *)\n"
        f"  event ScenarioProvider{'Allow' if provider_allow else 'Deny'}(aid_A, aid_B);\n"
        + ("  insert ProviderAuthorized(aid_A, aid_B);\n" if provider_allow else "")
        + f"  event ScenarioReceiver{'Allow' if receiver_allow else 'Deny'}(aid_A, aid_B);\n"
        + ("  insert ReceiverAuthorized(aid_A, aid_B);\n" if receiver_allow else "")
    )
    model = model[:scenario_begin] + scenario + model[scenario_end:]
    return "\n".join(line.rstrip() for line in model.splitlines()) + "\n"


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    for name, (provider_allow, receiver_allow) in SCENARIOS.items():
        destination = PROVERIF / f"agent_communication_authz_chat_{name}.pv"
        destination.write_text(
            build(source, provider_allow, receiver_allow), encoding="utf-8", newline="\n"
        )
        print(destination.relative_to(PROVERIF.parent))


if __name__ == "__main__":
    main()
