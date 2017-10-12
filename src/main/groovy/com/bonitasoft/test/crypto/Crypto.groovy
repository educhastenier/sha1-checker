package com.bonitasoft.test.crypto

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

/**
 * @author Emmanuel Duchastenier
 */
class Crypto {

    def LINE_SEPARATOR = System.lineSeparator()

    final Map checksumMap = ["ActorMemberPermissionRule.groovy"               : "0510a1aa823611442239058e2c5829aa92ecc532",
                             "ActorPermissionRule.groovy"                     : "0b457fb77caf7a66d1167e0e70fd1502f3b1adac",
                             "CaseContextPermissionRule.groovy"               : "762633a45c11f70a970344b176a5aa448a2e9ab5",
                             "CasePermissionRule.groovy"                      : "2626f1b435606eba6f7fc92922c3239f74965e96",
                             "CaseVariablePermissionRule.groovy"              : "c1aee4726352af3640f6c6dccb05047cbdbef3ad",
                             "CommentPermissionRule.groovy"                   : "7fb396db4c713a1643b34ac6d6b77d6867f6d9c8",
                             "ConnectorInstancePermissionRule.groovy"         : "5a350ac32bc0427f42f18c04050b15dd5d1a696a",
                             "DocumentPermissionRule.groovy"                  : "ab24186d10f98e7e3e760c810437ae83b9f3b3c8",
                             "ProcessConfigurationPermissionRule.groovy"      : "14f4c744d8c2d3f808295dc67fa1890882840505",
                             "ProcessConnectorDependencyPermissionRule.groovy": "7cf3d2e3f708d7d68af33e328eea6a8c179649a9",
                             "ProcessInstantiationPermissionRule.groovy"      : "348bbb4ecb73f31d2e9f9efbedf793ba672876f1",
                             "ProcessPermissionRule.groovy"                   : "970422ed0c3e0a8c2b041b1095710dbd2ea87e8f",
                             "ProcessResolutionProblemPermissionRule.groovy"  : "b9c8fb8e5f9b3ecd05f3af7fece6cac9baa75ddd",
                             "ProcessSupervisorPermissionRule.groovy"         : "bf52d8db2ba007c861d3bca1f6757c34c2136826",
                             "ProfileEntryPermissionRule.groovy"              : "8defb6d2d75ab04fd3d96d57277c0d8908773d6c",
                             "ProfilePermissionRule.groovy"                   : "a1e4cfd1136ac4355c1228475b19bf45de9c1b4f",
                             "TaskExecutionPermissionRule.groovy"             : "c226f62623233635d3b5593363bd4a9259256780",
                             "TaskPermissionRule.groovy"                      : "291162d21ef9a6ab9d7892b0dd00d2199fde44fe",
                             "UserPermissionRule.groovy"                      : "92d283255edced2a4e63313b8975b6cad1767cf8"]

    boolean isGroovyScriptFileUnchanged(String scriptName, byte[] scriptContent) {
        String reference = checksumMap.get(scriptName)

        MessageDigest sha1Digest = MessageDigest.getInstance("SHA1")
        byte[] sha1sum = sha1Digest.digest(new String(scriptContent, StandardCharsets.UTF_8).replaceAll("$LINE_SEPARATOR", '\n').bytes)
        StringBuilder sb = new StringBuilder()
        for (int i = 0; i < sha1sum.length; i++) {
            sb.append(Integer.toString((sha1sum[i] & 0xff) + 0x100, 16).substring(1))
        }
        def sha1Hexa = sb.toString()
        !isCustomGroovyScript(scriptName) && reference == sha1Hexa
    }

    boolean isCustomGroovyScript(String scriptName) {
        !checksumMap.containsKey(scriptName)
    }
}
