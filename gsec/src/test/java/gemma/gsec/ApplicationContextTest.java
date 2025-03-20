package gemma.gsec;

import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.SecurityConfig;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@ContextConfiguration(locations = { "classpath*:gemma/gsec/applicationContext-*.xml", "classpath:gemma/gsec/testContext.xml" })
public class ApplicationContextTest extends AbstractJUnit4SpringContextTests {

    @Autowired
    private AccessDecisionManager accessDecisionManager;

    /**
     * Test all the supported {@link org.springframework.security.access.annotation.Secured} config attribute.
     */
    @Test
    public void testSupportedSecuredConfigAttributes() {
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_READ" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_EDIT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_EDIT_IGNORE_TRANSIENT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_COLLECTION_READ" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_COLLECTION_EDIT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_COLLECTION_EDIT_IGNORE_TRANSIENT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_MAP_READ" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_MAP_EDIT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_MAP_EDIT_IGNORE_TRANSIENT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_MAP_VALUE_READ" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_MAP_VALUE_EDIT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "ACL_SECURABLE_MAP_VALUE_EDIT_IGNORE_TRANSIENT" ) ) );
        assertFalse( accessDecisionManager.supports( new SecurityConfig( "ACL_FOO" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "GROUP_USER" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "GROUP_ADMIN" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "GROUP_AGENT" ) ) );
        assertTrue( accessDecisionManager.supports( new SecurityConfig( "IS_AUTHENTICATED_ANONYMOUSLY" ) ) );
    }
}
