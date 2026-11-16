from support import Fixture, run, verify_signature
import json
from urllib.parse import parse_qs


class Handler(Fixture):
    def route(self, body):
        credentials = {"AccessKeyId": "test", "SecretAccessKey": "test", "Token": "metadata-token", "Expiration": "2099-01-01T00:00:00Z"}
        if self.path == "/latest/api/token":
            assert self.command == "PUT"
            assert self.headers["X-aws-ec2-metadata-token-ttl-seconds"] == "21600"
            self.reply(200, "imds-token")
            return
        if self.path.startswith("/latest/meta-data/"):
            assert self.headers["X-aws-ec2-metadata-token"] == "imds-token"
            self.reply(200, credentials if self.path.endswith("/role") else "role")
            return
        if self.path == "/container":
            assert self.headers["Authorization"] == "container-token"
            self.reply(200, credentials)
            return
        if self.path == "/sts":
            fields = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            action = fields["Action"]
            assert fields["RoleArn"] == "arn:aws:iam::123:role/test"
            if action == "AssumeRole":
                assert verify_signature(self, body) == "sts"
            else:
                assert fields["WebIdentityToken"] == "web-token"
                assert "Authorization" not in self.headers
            xml = "<Credentials><AccessKeyId>test</AccessKeyId><SecretAccessKey>test</SecretAccessKey><SessionToken>role-token</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials>"
            self.reply(200, f"<{action}Response><{action}Result>{xml}</{action}Result></{action}Response>")
            return
        assert verify_signature(self, body) == "ssm"
        target = self.headers["X-Amz-Target"]
        count = self.server.calls[target] = self.server.calls.get(target, 0) + 1
        if target == "Test.Retry" and count < 3:
            self.reply(400, {"__type": "ThrottlingException", "message": "retry"})
        elif target == "Test.Once":
            assert count == 1
            self.reply(503, {"__type": "ServiceUnavailable", "message": "once"})
        elif target == "Test.Refresh" and self.headers["X-Amz-Security-Token"] == "old":
            self.reply(403, {"__type": "ExpiredTokenException", "message": "expired"})
        else:
            self.reply(200, {"attempts": count})


if __name__ == "__main__":
    run(Handler)
