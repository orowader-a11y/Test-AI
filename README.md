# Default Mule Project

This repository contains a starter Mule 4 application scaffold.

## What is included

- `pom.xml` configured for Mule application packaging and HTTP connector.
- `mule-artifact.json` with minimum Mule runtime version.
- `src/main/mule/default.xml` with a basic HTTP listener flow (`GET /`).
- `src/main/resources/log4j2.xml` with simple console logging.

## Run

```bash
mvn clean package
```

Then run the artifact in Mule runtime (or open/import in Anypoint Studio).
