#FROM eclipse-temurin:17-jdk
#COPY target/editora-livros-api-0.0.1-SNAPSHOT.jar editoraSenai.jar
#ENTRYPOINT ["java","-jar","/editoraSenai.jar"]
#EXPOSE 8080


#FROM eclipse-temurin:17-jdk
#FROM eclipse-temurin:17-jdk-focal

#WORKDIR /api
#
#COPY .mvn/ .mvn
#COPY mvnw pom.xml ./
#RUN ./mvnw dependency:go-offline
#
#COPY target/editora-livros-api-0.0.1-SNAPSHOT.jar ./editoraSenai.jar
#EXPOSE 8080
#
#COPY src ./src
#ENTRYPOINT ["java","-jar","/api/editoraSenai.jar"]

#CMD ["./mvnw", "spring-boot:run"]


#FROM openjdk:8-jdk-alpine as build
FROM eclipse-temurin:17-jdk as build

WORKDIR /api

COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

RUN chmod +x ./mvnw
# Faça o download das dependencias do pom.xml
RUN ./mvnw dependency:go-offline -B

COPY src src

RUN ./mvnw package -DskipTests
RUN mkdir -p target/dependency && (cd target/dependency; jar -xf ../*.jar)

# Definição de produção para a imagem do Spring boot
#FROM openjdk:8-jre-alpine as production
FROM eclipse-temurin:17-jdk as production

ARG DEPENDENCY=/api/target/dependency

# Copiar as dependencias para o build artifact
COPY --from=build ${DEPENDENCY}/BOOT-INF/lib /api/lib
COPY --from=build ${DEPENDENCY}/META-INF /api/META-INF
COPY --from=build ${DEPENDENCY}/BOOT-INF/classes /api

# Rodar a aplicação Spring boot
ENTRYPOINT ["java", "-cp", "api:api/lib/*","br.senai.sc.editoralivros.EditoraLivrosApplication"]