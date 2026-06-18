## Shared impersonation token state for steal_token / make_token / rev2self.
when defined(windows):
  var gImpersonatedToken*: int = 0  # current duplicated HANDLE, 0 = none
