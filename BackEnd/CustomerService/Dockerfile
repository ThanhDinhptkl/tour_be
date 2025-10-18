FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/target/*.jar app.jar

# Chỉ giữ lại các biến cần thiết
ENV SPRING_PROFILES_ACTIVE=prod
ENV JWT_SECRET=pR8dXJZtG6qM9wKf3uYvL2sBzT4cV1oX5nA7mN0QWgE
ENV JAVA_OPTS="-Xmx512m -Xms256m"

EXPOSE 8083
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]