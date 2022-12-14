pipeline {
    agent  {
        label 'production'
    }
    stages {
        stage('Build and push dpkg') {
            steps {
                echo 'Compiling and packaging the dpkg file.'
                script {
                    sh 'make build'
                    sh 'curl -F package=@*.deb https://${env.TOKEN}@push.fury.io/trolleyesecurity/'
                    }
                }
            }
        }
    }
}