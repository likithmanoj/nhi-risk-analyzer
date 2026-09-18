from nhi.azure.session import get_authorization_client
def list_role_assignment() -> list:
    client = get_authorization_client()
    assignments = client.role_assignments.list_for_subscription()
    role_assignments = []
