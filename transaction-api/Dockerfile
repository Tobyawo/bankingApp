FROM openjdk:17
#EXPOSE 8086
ADD target/transaction-api.jar transaction-api.jar
ENTRYPOINT [\
"java",\
 "-jar", \
 "/transaction-api.jar"\
 ]
