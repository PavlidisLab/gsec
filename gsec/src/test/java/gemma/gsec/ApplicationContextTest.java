package gemma.gsec;

import org.junit.Test;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractJUnit4SpringContextTests;

@ContextConfiguration(locations = {"classpath*:gemma/gsec/applicationContext-*.xml", "classpath:gemma/gsec/testContext.xml"})
public class ApplicationContextTest extends AbstractJUnit4SpringContextTests {

    @Test
    public void test() {
    }
}
