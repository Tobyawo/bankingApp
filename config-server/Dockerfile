FROM openjdk:17
ADD target/config-server.jar config-server.jar
ENTRYPOINT [ \
  "java", \
  "-jar", \
  "/config-server.jar" \
]
