package org.joget.plugin.kerberos;

import org.joget.directory.model.User;
import org.joget.directory.model.service.DirectoryManager;
import java.io.Serializable;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class KerberosUserDetailsService implements UserDetailsService, Serializable {

    transient
    @Autowired
    @Qualifier("main")
    private DirectoryManager directoryManager;

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        if (username.contains("@")) {
            username = username.substring(0, username.indexOf("@"));
        }
        final User user = getDirectoryManager().getUserByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        UserDetails details = new WorkflowUserDetails(user);
        return details;
    }

    public DirectoryManager getDirectoryManager() {
        return directoryManager;
    }

    public void setDirectoryManager(DirectoryManager directoryManager) {
        this.directoryManager = directoryManager;
    }
}
