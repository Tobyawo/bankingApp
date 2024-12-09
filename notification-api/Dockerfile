FROM openjdk:17
#EXPOSE 8086
ADD target/notification-api.jar notification-api.jar
ENTRYPOINT [\
"java",\
 "-jar", \
 "/notification-api.jar"\
 ]
