pipeline {
    agent  {
        label "production"
    }
    environment {
        TOKEN = credentials('fury-io-token')
      }
    stages {
        stage("Build and push dpkg") {
            steps {
                echo "Compiling and packaging the dpkg file."
                script {
                    sh "make build"
                    sh "curl -F package=@ccscanner_2.0.2-0ubuntu_amd64.deb https://$TOKEN@push.fury.io/trolleyesecurity/"
                }
            }
        }
    }
}