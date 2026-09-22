FROM eclipse-temurin:26-jre
COPY target/jwtValidator-0.0.1-SNAPSHOT.jar jwtValidator.jar
EXPOSE 80
ENTRYPOINT ["java","-jar","jwtValidator.jar"]