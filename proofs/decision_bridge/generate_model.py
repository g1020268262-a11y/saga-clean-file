"""Reconstruct scenario input; whitelist comment changes; freeze all other bytes."""
import json
from bridge import MODEL, VERSION, digest, generate, relative_file

TEMPLATE_SHA256 = "e6ffbd5acebd3aa1f05ea7942c4f7eb23d4469357c7a01fea082de2b2e8ab121"
TEMPLATE_STATEMENTS = ("insert ScenarioSpecDeny(BuggyPolicy, aid_B);",
                       "insert ScenarioImplAllow(BuggyPolicy, aid_B);")
COMMENT_NORMALIZATIONS = (
    ("(* 动态生成属于本次会话的 Ephemeral Token，完美实现会话隔离 *)",
     "(* Fresh symbolic token for this modeled execution. *)"),
    ("(* 1. 保留你的出处证明：证明底层的 Token 签发与密码学验证逻辑没被破坏 *)",
     "(* Correspondence query relating modeled ChatAccept events to prior TokenIssue events. *)"),
    ("(* 2. 端到端越权查询：触发攻击的最终状态是否可达？ *)",
     "(* ChatAccept reachability query under the modeled authorization-divergence scenario. *)"),
)


def split_template(source):
    eol = b"\r\n" if b"\r\n" in source else b"\n"
    template_block = eol.join(b"  " + line.encode() for line in TEMPLATE_STATEMENTS) + eol
    if source.count(template_block) != 1:
        raise ValueError("Scenario block missing or ambiguous")
    index = source.index(template_block)
    return source[:index], source[index + len(template_block):], eol


def normalize_comments(content):
    for original, neutral in COMMENT_NORMALIZATIONS:
        old, new = original.encode("utf-8"), neutral.encode("ascii")
        if content.count(old) != 1 or new in content:
            raise ValueError("Approved comment missing or ambiguous")
        content = content.replace(old, new, 1)
    return content


def validate_structure(body, source, generated_block):
    """Strict bytes comparison, not generic comment removal or token equivalence."""
    prefix, suffix, _ = split_template(source)
    expected = normalize_comments(prefix + generated_block + suffix)
    if body != expected:
        raise ValueError("Unexpected change outside approved scenario/comment transformation")


def reconstruct(result_bytes):
    result = json.loads(result_bytes)
    fragment = generate(result)
    if fragment is None:
        raise ValueError("Frozen consequence template requires Deny/Allow decision pair")
    source = relative_file(MODEL).read_bytes()
    if digest(source) != TEMPLATE_SHA256:
        raise ValueError("Frozen template hash mismatch")
    prefix, suffix, eol = split_template(source)
    statements = [line for line in fragment.splitlines() if line.startswith("insert ")]
    if len(statements) != 2:
        raise ValueError("Expected exactly two derived scenario inserts")
    generated_block = eol.join(b"  " + line.encode("ascii") for line in statements) + eol
    body = normalize_comments(prefix + generated_block + suffix)
    validate_structure(body, source, generated_block)
    return result, body, generated_block


def derive_model(result_bytes):
    result, body, generated_block = reconstruct(result_bytes)
    header = (f"(* Derived by {VERSION}; no Python refinement claim.\n"
              f"evaluation_fingerprint: {result['evaluation_fingerprint']}\n"
              f"bridge_result_sha256: {digest(result_bytes)}\n"
              f"source_model: {MODEL}\nsource_model_sha256: {TEMPLATE_SHA256}\n"
              f"generated_scenario_block_sha256: {digest(generated_block)}\n"
              "Scenario reconstructed from the checked decision pair; approved comments normalized.\n*)\n").encode("ascii")
    return header + body
