package org.zalando.cassandra.auth.oauth2;

import com.google.common.collect.ImmutableSet;
import org.apache.cassandra.auth.CassandraRoleManager;

import java.util.Set;

/**
 * Created by jmussler on 14.02.17.
 */
public class Oauth2RoleManager extends CassandraRoleManager {

    public Oauth2RoleManager() {
        super();
    }

    // We need this to overwrite the options in Cassandra's original RoleManager :(
    public Set<Option> alterableOptions()
    {
        return ImmutableSet.of(Option.PASSWORD);
    }

    public Set<Option> supportedOptions()
    {
        return ImmutableSet.of(Option.LOGIN, Option.SUPERUSER, Option.PASSWORD);
    }
}
