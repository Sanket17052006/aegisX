import re
import grpc
from concurrent import futures
import security_service_pb2 as pb2
import security_service_pb2_grpc as pb2_grpc

DANGEROUS_PATTERNS = [
    r"\bDROP\s+TABLE\b",
    r"\bDELETE\s+FROM\b",
    r"\bOR\b[\s\S]*\b1\s*=\s*1\b",
    r"\bUNION\s+SELECT\b",
    r"(--)",
]

class SecurityService(pb2_grpc.SecurityServiceServicer):
    def InspectPayload(self, request, context):
        body = request.request_body
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return pb2.InspectResponse(approved=False, reason=f"Blocked: matched {pattern}")
        return pb2.InspectResponse(approved=True, reason="Payload is clean")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_SecurityServiceServicer_to_server(SecurityService(), server)
    server.add_insecure_port("[::]:50051")
    server.start()
    print("Security Engine listening on port 50051...")
    server.wait_for_termination()

if __name__ == "__main__":
    serve()