pipeline {
    agent  {
        label "production"
    }
    stages {
        stage("Build and push dpkg") {
            steps {
                echo "Compiling and packaging the dpkg file."
                script {
                    withCredentials([string(credentialsId: "fury-io-token", variable: "TOKEN")]) {
                        sh "make build"
                        sh "curl -F package=@*.deb https://${TOKEN}@push.fury.io/trolleyesecurity/"
                    }
                }
            }
        }
    }
}