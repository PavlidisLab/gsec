package gemma.gsec;

import gemma.gsec.authentication.UserManager;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

@ContextConfiguration(locations = { "classpath*:gemma/gsec/applicationContext-*.xml", "classpath*:gemma.gsec/testContext.xml" })
public class ApplicationContextTest extends AbstractJUnit4SpringContextTests {

    @Autowired
    private UserManager userManager;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Test
    public void test() {
    }
}
