# order-service sample

A minimal Java 17 service built with the Gradle wrapper (`./gradlew test installDist`) and run with
`build/install/order-service/bin/order-service` on `PORT`. It stands in for a backend service that is too big to build
inside a Code Interpreter microVM: `examples/workload_demo.py` edits it in the sandbox, builds and runs it on an EKS
workload Pod, and lets the agent fix a seeded bug there.
