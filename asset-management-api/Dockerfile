FROM openjdk:17
#EXPOSE 8086
ADD target/asset-management-api.jar asset-management-api.jar
ENTRYPOINT [ \
  "java", \
  "-jar", \
  "/asset-management-api.jar" \
]
