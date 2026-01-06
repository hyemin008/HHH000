from __future__ import annotations

import argparse
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError


# -----------------------------
# Helpers
# -----------------------------
def safe_call(fn, *args, **kwargs) -> Tuple[bool, Any]:
    try:
        return True, fn(*args, **kwargs)
    except ClientError as e:
        return False, e
    except Exception as e:
        return False, e


def prompt_int(msg: str, min_v: int, max_v: int) -> int:
    while True:
        s = input(msg).strip()
        if s.isdigit():
            v = int(s)
            if min_v <= v <= max_v:
                return v
        print(f"  입력 오류: {min_v}~{max_v} 사이 숫자를 입력하세요.")


def confirm_phrase(phrase: str) -> bool:
    print("\n[확인] 아래 문구를 그대로 입력해야 삭제가 진행됩니다.")
    print(f"  >>> {phrase}")
    typed = input("입력: ").strip()
    if typed != phrase:
        print("  ❌ 확인 문구가 일치하지 않아 취소했습니다.")
        return False
    return True


def show_identity(session: boto3.Session) -> None:
    sts = session.client("sts")
    ok, res = safe_call(sts.get_caller_identity)
    if ok:
        print("\n[현재 자격증명]")
        print(f"  Account : {res.get('Account')}")
        print(f"  Arn     : {res.get('Arn')}")
        print(f"  UserId  : {res.get('UserId')}")
    else:
        print("\n[현재 자격증명 확인 실패]")
        print(f"  {res}")


# -----------------------------
# S3
# -----------------------------
def s3_list_buckets(session: boto3.Session) -> List[str]:
    s3 = session.client("s3")
    ok, res = safe_call(s3.list_buckets)
    if not ok:
        raise RuntimeError(f"S3 list_buckets 실패: {res}")
    return [b["Name"] for b in (res.get("Buckets") or []) if b.get("Name")]


def s3_list_some_objects(session: boto3.Session, bucket: str, prefix: str = "", limit: int = 30) -> List[str]:
    s3 = session.client("s3")
    out: List[str] = []
    token = None
    while len(out) < limit:
        kwargs = {"Bucket": bucket, "MaxKeys": min(1000, limit - len(out))}
        if prefix:
            kwargs["Prefix"] = prefix
        if token:
            kwargs["ContinuationToken"] = token

        ok, res = safe_call(s3.list_objects_v2, **kwargs)
        if not ok:
            # 권한 없거나, 버킷 정책 문제 등
            return [f"[ERROR] {res}"]

        for obj in res.get("Contents", []) or []:
            k = obj.get("Key")
            if k:
                out.append(k)
        if res.get("IsTruncated"):
            token = res.get("NextContinuationToken")
        else:
            break
    return out


def s3_abort_multipart(session: boto3.Session, bucket: str, prefix: Optional[str]) -> None:
    s3 = session.client("s3")
    ok, res = safe_call(s3.list_multipart_uploads, Bucket=bucket)
    if not ok:
        # 권한 없으면 그냥 넘어감
        print(f"  [S3] list_multipart_uploads 실패(권한 부족 가능): {res}")
        return

    uploads = res.get("Uploads", []) or []
    for u in uploads:
        key = u.get("Key")
        upload_id = u.get("UploadId")
        if not key or not upload_id:
            continue
        if prefix and not key.startswith(prefix):
            continue

        ok2, res2 = safe_call(s3.abort_multipart_upload, Bucket=bucket, Key=key, UploadId=upload_id)
        if ok2:
            print(f"  [S3] 멀티파트 업로드 중단: {key} ({upload_id})")
        else:
            print(f"  [S3] 멀티파트 중단 실패: {key} -> {res2}")


def s3_delete_versions(session: boto3.Session, bucket: str, prefix: Optional[str]) -> int:
    """
    Delete all object versions + delete markers (works also for non-versioned buckets).
    Returns deleted count (approx).
    """
    s3 = session.client("s3")
    paginator = s3.get_paginator("list_object_versions")

    deleted_count = 0
    batch: List[Dict[str, str]] = []

    def flush():
        nonlocal deleted_count, batch
        if not batch:
            return
        ok, res = safe_call(
            s3.delete_objects,
            Bucket=bucket,
            Delete={"Objects": batch, "Quiet": True},
        )
        if ok:
            deleted = res.get("Deleted", []) or []
            errors = res.get("Errors", []) or []
            deleted_count += len(deleted)
            if errors:
                print(f"  [S3] delete_objects 일부 오류: {errors[:3]}{'...' if len(errors) > 3 else ''}")
        else:
            print(f"  [S3] delete_objects 실패: {res}")
        batch = []

    try:
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix or ""):
            versions = page.get("Versions", []) or []
            markers = page.get("DeleteMarkers", []) or []

            for v in versions:
                k = v.get("Key")
                vid = v.get("VersionId")
                if k and vid:
                    batch.append({"Key": k, "VersionId": vid})
                    if len(batch) >= 1000:
                        flush()

            for m in markers:
                k = m.get("Key")
                vid = m.get("VersionId")
                if k and vid:
                    batch.append({"Key": k, "VersionId": vid})
                    if len(batch) >= 1000:
                        flush()

        flush()
    except ClientError as e:
        print(f"  [S3] list_object_versions 실패: {e}")
        print("       (권한 부족, 버킷 없음, Object Lock/Retention 등 가능)")
        return deleted_count

    return deleted_count


def s3_delete_prefix(session: boto3.Session, bucket: str, prefix: str) -> None:
    print(f"\n[S3] 삭제 대상: s3://{bucket}/{prefix}")
    some = s3_list_some_objects(session, bucket, prefix=prefix, limit=20)
    print("\n  [미리보기] (최대 20개)")
    for k in some:
        print("   -", k)

    phrase = f"DELETE S3 PREFIX s3://{bucket}/{prefix}"
    if not confirm_phrase(phrase):
        return

    print("\n  [진행] 멀티파트 업로드 중단(해당 prefix)")
    s3_abort_multipart(session, bucket, prefix=prefix)

    print("  [진행] 버전/삭제마커 포함 객체 삭제(해당 prefix)")
    cnt = s3_delete_versions(session, bucket, prefix=prefix)
    print(f"  [완료] 삭제 처리 수(대략): {cnt}")


def s3_empty_and_delete_bucket(session: boto3.Session, bucket: str) -> None:
    print(f"\n[S3] 버킷 전체 삭제 대상: {bucket}")
    some = s3_list_some_objects(session, bucket, prefix="", limit=20)
    print("\n  [미리보기] (최대 20개)")
    for k in some:
        print("   -", k)

    phrase = f"DELETE S3 BUCKET {bucket}"
    if not confirm_phrase(phrase):
        return

    print("\n  [진행] 멀티파트 업로드 중단(전체)")
    s3_abort_multipart(session, bucket, prefix=None)

    print("  [진행] 버전/삭제마커 포함 객체 전체 삭제")
    cnt = s3_delete_versions(session, bucket, prefix=None)
    print(f"  [진행] 삭제 처리 수(대략): {cnt}")

    s3 = session.client("s3")
    print("  [진행] 버킷 삭제")
    ok, res = safe_call(s3.delete_bucket, Bucket=bucket)
    if ok:
        print(f"  ✅ 버킷 삭제 완료: {bucket}")
    else:
        print(f"  ❌ delete_bucket 실패: {res}")
        print("     (버킷 정책/권한, Object Lock, 남은 객체 등 확인 필요)")


# -----------------------------
# IAM User Delete
# -----------------------------
def iam_list_users(session: boto3.Session) -> List[str]:
    iam = session.client("iam")
    users: List[str] = []
    marker = None
    while True:
        kwargs = {}
        if marker:
            kwargs["Marker"] = marker
        ok, res = safe_call(iam.list_users, **kwargs)
        if not ok:
            raise RuntimeError(f"IAM list_users 실패: {res}")
        for u in res.get("Users", []) or []:
            if u.get("UserName"):
                users.append(u["UserName"])
        if res.get("IsTruncated"):
            marker = res.get("Marker")
        else:
            break
    return users


def iam_delete_user_fully(session: boto3.Session, user_name: str) -> None:
    iam = session.client("iam")
    print(f"\n[IAM] 삭제 대상 유저: {user_name}")

    phrase = f"DELETE IAM USER {user_name}"
    if not confirm_phrase(phrase):
        return

    # 1) groups
    ok, res = safe_call(iam.list_groups_for_user, UserName=user_name)
    if ok:
        for g in res.get("Groups", []) or []:
            gname = g.get("GroupName")
            if not gname:
                continue
            ok2, res2 = safe_call(iam.remove_user_from_group, GroupName=gname, UserName=user_name)
            if ok2:
                print(f"  [IAM] 그룹 제거: {gname}")
            else:
                print(f"  [IAM] 그룹 제거 실패 {gname}: {res2}")
    else:
        print(f"  [IAM] list_groups_for_user 실패: {res}")

    # 2) detach managed policies
    ok, res = safe_call(iam.list_attached_user_policies, UserName=user_name)
    if ok:
        for p in res.get("AttachedPolicies", []) or []:
            arn = p.get("PolicyArn")
            if not arn:
                continue
            ok2, res2 = safe_call(iam.detach_user_policy, UserName=user_name, PolicyArn=arn)
            if ok2:
                print(f"  [IAM] 관리형 정책 분리: {arn}")
            else:
                print(f"  [IAM] 관리형 정책 분리 실패 {arn}: {res2}")
    else:
        print(f"  [IAM] list_attached_user_policies 실패: {res}")

    # 3) delete inline policies
    ok, res = safe_call(iam.list_user_policies, UserName=user_name)
    if ok:
        for pn in res.get("PolicyNames", []) or []:
            ok2, res2 = safe_call(iam.delete_user_policy, UserName=user_name, PolicyName=pn)
            if ok2:
                print(f"  [IAM] 인라인 정책 삭제: {pn}")
            else:
                print(f"  [IAM] 인라인 정책 삭제 실패 {pn}: {res2}")
    else:
        print(f"  [IAM] list_user_policies 실패: {res}")

    # 4) access keys
    ok, res = safe_call(iam.list_access_keys, UserName=user_name)
    if ok:
        for k in res.get("AccessKeyMetadata", []) or []:
            kid = k.get("AccessKeyId")
            if not kid:
                continue
            ok2, res2 = safe_call(iam.delete_access_key, UserName=user_name, AccessKeyId=kid)
            if ok2:
                print(f"  [IAM] 액세스키 삭제: {kid}")
            else:
                print(f"  [IAM] 액세스키 삭제 실패 {kid}: {res2}")
    else:
        print(f"  [IAM] list_access_keys 실패: {res}")

    # 5) login profile
    ok, res = safe_call(iam.delete_login_profile, UserName=user_name)
    if ok:
        print("  [IAM] 콘솔 로그인 프로필 삭제")
    else:
        # NoSuchEntity는 무시
        if isinstance(res, ClientError):
            code = res.response.get("Error", {}).get("Code", "")
            if code not in ("NoSuchEntity", "NoSuchEntityException"):
                print(f"  [IAM] delete_login_profile 실패: {res}")

    # 6) deactivate MFA devices
    ok, res = safe_call(iam.list_mfa_devices, UserName=user_name)
    if ok:
        for m in res.get("MFADevices", []) or []:
            serial = m.get("SerialNumber")
            if not serial:
                continue
            ok2, res2 = safe_call(iam.deactivate_mfa_device, UserName=user_name, SerialNumber=serial)
            if ok2:
                print(f"  [IAM] MFA 비활성화: {serial}")
            else:
                print(f"  [IAM] MFA 비활성화 실패 {serial}: {res2}")
    else:
        print(f"  [IAM] list_mfa_devices 실패: {res}")

    # Finally delete user
    ok, res = safe_call(iam.delete_user, UserName=user_name)
    if ok:
        print(f"  ✅ IAM 유저 삭제 완료: {user_name}")
    else:
        print(f"  ❌ delete_user 실패: {res}")
        print("     (남아있는 리소스가 있거나 권한 부족이면 삭제가 막힙니다.)")


# -----------------------------
# Menu
# -----------------------------
def menu_s3(session: boto3.Session) -> None:
    try:
        buckets = s3_list_buckets(session)
    except Exception as e:
        print(f"[S3] 버킷 목록 조회 실패: {e}")
        return

    if not buckets:
        print("[S3] 버킷이 없습니다.")
        return

    print("\n[S3] 버킷 목록")
    for i, b in enumerate(buckets, start=1):
        print(f"  {i}. {b}")
    print("  0. 뒤로가기")

    sel = prompt_int("선택(번호): ", 0, len(buckets))
    if sel == 0:
        return

    bucket = buckets[sel - 1]
    print(f"\n[S3] 선택됨: {bucket}")
    print("  1) 특정 prefix만 삭제")
    print("  2) 버킷 전체 비우고(버전 포함) 버킷 삭제")
    print("  0) 취소")

    act = prompt_int("작업 선택: ", 0, 2)
    if act == 0:
        return
    if act == 1:
        prefix = input("prefix 입력 (예: uploads/ , 비우면 전체): ").strip()
        if prefix == "":
            print("prefix가 비어있으면 '전체 삭제'가 됩니다. 안전을 위해 취소했습니다.")
            return
        s3_delete_prefix(session, bucket, prefix)
    elif act == 2:
        s3_empty_and_delete_bucket(session, bucket)


def menu_iam(session: boto3.Session) -> None:
    try:
        users = iam_list_users(session)
    except Exception as e:
        print(f"[IAM] 유저 목록 조회 실패: {e}")
        return

    if not users:
        print("[IAM] 유저가 없습니다.")
        return

    print("\n[IAM] 유저 목록")
    for i, u in enumerate(users, start=1):
        print(f"  {i}. {u}")
    print("  0. 뒤로가기")

    sel = prompt_int("선택(번호): ", 0, len(users))
    if sel == 0:
        return

    user_name = users[sel - 1]
    # 안전: 자기 자신 삭제 방지(원하면 주석 처리)
    me = session.client("sts")
    ok, who = safe_call(me.get_caller_identity)
    if ok and isinstance(who, dict) and user_name in (who.get("Arn") or ""):
        print("\n⚠️ 현재 실행 주체(본인) 삭제는 안전을 위해 막았습니다.")
        return

    iam_delete_user_fully(session, user_name)


def main():
    ap = argparse.ArgumentParser(description="List resources and delete by selection (S3 / IAM) - VERY DANGEROUS.")
    ap.add_argument("--profile", default=None, help="AWS CLI profile name (optional)")
    ap.add_argument("--region", default=None, help="Default region (optional)")
    args = ap.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    except ProfileNotFound as e:
        print(f"[ERROR] Profile not found: {e}")
        return
    except NoCredentialsError:
        print("[ERROR] No AWS credentials. Run aws configure or set AWS_PROFILE.")
        return

    show_identity(session)

    while True:
        print("\n==============================")
        print("메뉴")
        print("  1) S3 (버킷/prefix 삭제)")
        print("  2) IAM (유저 삭제)")
        print("  0) 종료")
        choice = prompt_int("선택: ", 0, 2)

        if choice == 0:
            print("종료합니다.")
            return
        elif choice == 1:
            menu_s3(session)
        elif choice == 2:
            menu_iam(session)


if __name__ == "__main__":
    main()
