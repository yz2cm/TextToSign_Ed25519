# -*- coding: utf-8 -*-
"""
text_sign.py ― テキストへの Ed25519 署名を作るツール

機能は3つだけ:
  1. keygen : Ed25519 の鍵ペアを生成する
  2. sign   : 秘密鍵とテキストを指定して署名を生成する
  3. verify : 公開鍵・テキスト・署名を指定して検証する

署名の形式:
  Base64( 署名64バイト ) ＝ 常に 88 文字（テキストの長さによらない）
  Ed25519 の署名は、それ単体から元のテキストを復元することはできない。
  検証は「テキスト＋署名＋公開鍵」の3点がそろって初めて可能になる
  （署名とはそういうもの、という標準的な方式）。
  署名できるテキストは UUID に限らず、名前・フレーズ・URL など任意の文字列。

必要なもの:
  pip install cryptography

使い方:
  python text_sign.py keygen
  python text_sign.py sign [--key 秘密鍵ファイル] [--text テキスト]
  python text_sign.py verify --sig <署名> [--text テキスト] [--pub <公開鍵Base64>]
      （--text を省略すると既定の対象テキスト、--pub を省略すると public_key.txt を読む）

生成されるファイル（このスクリプトと同じフォルダ）:
  private_key.pem   秘密鍵（パスフレーズで暗号化。絶対に他人に渡さない・失くさない）
  public_key.txt    公開鍵の Base64
  declaration.txt   公開鍵の宣言文面案（対象テキストと公開鍵入り）
  signature.txt     署名（sign 実行時に保存）
"""

import argparse
import base64
import getpass
import os
import sys

# ★ 署名対象テキストの既定値（--text で上書き可能。宣言で公開したものと一致させること）
DEFAULT_TEXT = "ffffffff-ffff-ffff-ffff-ffffffffffff"
BASE = os.path.dirname(os.path.abspath(__file__))
PRIV_PATH = os.path.join(BASE, "private_key.pem")
PUB_PATH = os.path.join(BASE, "public_key.txt")
DECL_PATH = os.path.join(BASE, "declaration.txt")
SIG_PATH = os.path.join(BASE, "signature.txt")

SIG_LEN = 64  # Ed25519 の署名は 64 バイト固定


def passphrase(for_new=False) -> bytes:
    env = os.environ.get("SIGN_PASSPHRASE")
    if env:
        return env.encode()
    while True:
        p = getpass.getpass("秘密鍵のパスフレーズ: ")
        if not for_new:
            return p.encode()
        p2 = getpass.getpass("もう一度入力してください: ")
        if p == p2 and len(p) >= 8:
            return p.encode()
        print("パスフレーズが一致しないか短すぎます（8文字以上）。もう一度。")


# ---------- 1. 鍵ペアの生成 ----------
def cmd_keygen():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    if os.path.exists(PRIV_PATH):
        ans = input("秘密鍵が既にあります。上書きすると今までの署名と鍵が合わなくなります。上書きしますか？ [y/N] ")
        if ans.lower() != "y":
            print("中止しました。")
            return
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(passphrase(for_new=True)),
    )
    with open(PRIV_PATH, "wb") as f:
        f.write(pem)
    pub_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")
    with open(PUB_PATH, "w", encoding="utf-8") as f:
        f.write(pub_b64 + "\n")
    declaration = (
        "【署名について】\n"
        "私が作成する署名（Base64文字列）は、次の公開鍵で検証できます。\n"
        f"署名対象テキスト: {DEFAULT_TEXT}\n"
        f"公開鍵(Ed25519): {pub_b64}\n"
        "検証には、対象テキストと署名とこの公開鍵を使います。"
    )
    with open(DECL_PATH, "w", encoding="utf-8") as f:
        f.write(declaration + "\n")
    print("鍵ペアを生成しました。")
    print(f"  秘密鍵 : {PRIV_PATH}（パスフレーズで保護。厳重に保管し、バックアップを取ること）")
    print(f"  公開鍵 : {PUB_PATH}")
    print(f"  宣言文面案: {DECL_PATH}")
    print()
    print("公開鍵(Base64):", pub_b64)


# ---------- 2. 署名の生成 ----------
def cmd_sign(key_path, text):
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    if not os.path.exists(key_path):
        sys.exit(f"秘密鍵が見つかりません: {key_path}（先に keygen を実行してください）")
    with open(key_path, "rb") as f:
        key = load_pem_private_key(f.read(), password=passphrase())
    sig = key.sign(text.encode("utf-8"))
    sig_b64 = base64.b64encode(sig).decode("ascii")
    with open(SIG_PATH, "w", encoding="utf-8") as f:
        f.write(sig_b64 + "\n")
    print(f"テキスト: {text}")
    print("署名:")
    print(sig_b64)
    print(f"（{SIG_PATH} にも保存しました。Ed25519 の署名は決定的なので、同じテキストには常に同じ署名になります）")


# ---------- 3. 検証 ----------
def cmd_verify(pub_b64, text, sig_b64):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    if not pub_b64:
        if os.path.exists(PUB_PATH):
            with open(PUB_PATH, encoding="utf-8") as f:
                pub_b64 = f.read().strip()
        else:
            sys.exit("--pub で公開鍵(Base64)を指定してください。")
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64.strip()))
        sig = base64.b64decode(sig_b64.strip())
    except Exception:
        sys.exit("公開鍵または署名の Base64 形式が正しくありません。")
    if len(sig) != SIG_LEN:
        print(f"検証NG：署名の長さが正しくありません（{SIG_LEN}バイトであるはず）。")
        return
    print(f"テキスト: {text}")
    try:
        pub.verify(sig, text.encode("utf-8"))
        print("検証OK：この署名は、そのテキストに対して、公開鍵に対応する秘密鍵で作成されています。")
    except InvalidSignature:
        print("検証NG：署名が一致しません（そのテキストはその秘密鍵で署名されていません）。")


def main():
    parser = argparse.ArgumentParser(description="テキストへの Ed25519 署名を作るツール")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("keygen", help="鍵ペアを生成する")

    p_sign = sub.add_parser("sign", help="秘密鍵とテキストを指定して署名を生成する")
    p_sign.add_argument("--key", default=PRIV_PATH, help="秘密鍵ファイル（既定: private_key.pem）")
    p_sign.add_argument("--text", default=DEFAULT_TEXT, help="署名するテキスト（既定: スクリプト内の対象テキスト）")

    p_verify = sub.add_parser("verify", help="公開鍵・テキスト・署名を指定して検証する")
    p_verify.add_argument("--pub", default=None, help="公開鍵(Base64)。省略時は public_key.txt を読む")
    p_verify.add_argument("--text", default=DEFAULT_TEXT, help="署名されたテキスト（既定: スクリプト内の対象テキスト）")
    p_verify.add_argument("--sig", required=True, help="署名(Base64)")

    args = parser.parse_args()
    if args.cmd == "keygen":
        cmd_keygen()
    elif args.cmd == "sign":
        cmd_sign(args.key, args.text)
    elif args.cmd == "verify":
        cmd_verify(args.pub, args.text, args.sig)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
