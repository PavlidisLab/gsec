package gemma.gsec;

import gemma.gsec.authentication.UserManager;
import org.junit.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

@ContextConfiguration(locations = { "classpath*:gemma/gsec/applicationContext-*.xml", "classpath*:gemma.gsec/testContext.xml" })
public class ApplicationContextTest extends AbstractJUnit4SpringContextTests {

    @Configuration
    public class ContextConfiguration {

        @Bean
        public UserManager userManager() {
            return new UserManagerImpl();
        }
    }

    @Test
    public void test() {

    }
}
