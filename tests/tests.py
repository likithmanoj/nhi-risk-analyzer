from nhi.aws import iam


def test_managed_policy():
    managed = iam.get_managed_policy(
        "arn:aws:iam::640928554959:policy/pam-infrastructure-automation-suite-dev-runner-policy"
    )

    print("========== Managed Policy ==========")
    print("Type:", type(managed["PolicyDocument"]))
    print("Statement Type:", type(managed["PolicyDocument"]["Statement"]))
    print("First Statement:", managed["PolicyDocument"]["Statement"][0])
    print()


def test_user_inline_policy():
    user_inline = iam.get_user_inline_policy(
        "terraform",
        "inlinePolicyforTesting"
    )

    print("========== User Inline Policy ==========")
    print("Type:", type(user_inline["PolicyDocument"]))
    print("Statement Type:", type(user_inline["PolicyDocument"]["Statement"]))
    print("First Statement:", user_inline["PolicyDocument"]["Statement"][0])
    print()


def test_role_inline_policy():
    role_inline = iam.get_role_inline_policy(
        "<ROLE_NAME>",
        "<INLINE_POLICY_NAME>"
    )

    print("========== Role Inline Policy ==========")
    print("Type:", type(role_inline["PolicyDocument"]))
    print("Statement Type:", type(role_inline["PolicyDocument"]["Statement"]))
    print("First Statement:", role_inline["PolicyDocument"]["Statement"][0])
    print()


def test_group_inline_policy():
    group_inline = iam.get_group_inline_policy(
        "<GROUP_NAME>",
        "<INLINE_POLICY_NAME>"
    )

    print("========== Group Inline Policy ==========")
    print("Type:", type(group_inline["PolicyDocument"]))
    print("Statement Type:", type(group_inline["PolicyDocument"]["Statement"]))
    print("First Statement:", group_inline["PolicyDocument"]["Statement"][0])
    print()


if __name__ == "__main__":
    test_managed_policy()
    test_user_inline_policy()

    # Uncomment once you've created test resources.
    # test_role_inline_policy()
    # test_group_inline_policy()