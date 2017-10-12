package com.bonitasoft.test.crypto

import static org.assertj.core.api.Assertions.assertThat

import org.junit.Test

/**
 * @author Emmanuel Duchastenier
 */
class CryptoTest {

    @Test
    void should_detect_changed_file() throws Exception {
        // given:
        final Crypto crypto = new Crypto()
        def referenceFileContent = this.getClass().getResource("/to7_6_0/ActorMemberPermissionRule.groovy.txt").bytes

        // when:
        final boolean fileUnchanged = crypto.isGroovyScriptFileUnchanged("ActorMemberPermissionRule.groovy", referenceFileContent)

        // then:
        assertThat(fileUnchanged).isTrue()
    }
}