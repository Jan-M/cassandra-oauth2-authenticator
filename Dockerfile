FROM registry.opensource.zalan.do/stups/planb-cassandra-3:cd-66

COPY target/oauth2authenticator-3.9.jar /usr/share/cassandra/lib

ENV AUTHENTICATOR org.zalando.cassandra.auth.oauth2.Oauth2Authenticator
ENV ROLE_MANAGER org.zalando.cassandra.auth.oauth2.Oauth2RoleManager

CMD planb-cassandra.sh
