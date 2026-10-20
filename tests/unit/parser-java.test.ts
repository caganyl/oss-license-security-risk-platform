/**
 * REQ-011 P-40 — Java/Kotlin (`gradle.lockfile` > `pom.xml` > `build.gradle(.kts)`)
 * parser: goldens (AC-P40-1), source priority (AC-P40-2), broken files
 * (AC-P40-3), XML DOCTYPE rejection (AC-P40-4), versionless declarations
 * (AC-P40-6), pom property / dependencyManagement resolution (R-2) and the
 * best-effort Gradle DSL reading (R-1).
 */
import { describe, expect, it } from 'vitest';
import { isExactMavenVersion, isGradleConfiguration, lexGradle, parseGradleLockfile, parseGradleScript, parsePom } from '../../src/scanner/parsers/java';
import { PARSER_MESSAGES } from '../../src/scanner/parsers/kit';
import type { ScannedDependency } from '../../src/types/scan';
import { expectEcosystemGolden, parseEcosystemCase } from '../helpers/ecosystemGolden';

const CASES = ['gradle-lockfile', 'pom-properties', 'gradle-groovy', 'gradle-kts', 'priority', 'broken'] as const;

function rows(caseName: string): ScannedDependency[] {
  return parseEcosystemCase('java', 'java', caseName).dependencies;
}

function brief(list: readonly ScannedDependency[]): string[] {
  return list.map((d) => `${d.manifest_path}|${d.name}@${d.version ?? '-'}|${d.scope}|${d.manifest_file}|${d.declared_range ?? '-'}`);
}

describe('REQ-011 AC-P40-1: Java goldens', () => {
  for (const c of CASES) it(c, () => expectEcosystemGolden('java', 'java', c));
});

describe('REQ-011 P-40: gradle.lockfile', () => {
  it('exact versions; test-only configurations -> dev; declared in the build file -> direct (declaration as declared_range), else transitive', () => {
    expect(brief(rows('gradle-lockfile'))).toEqual([
      // only in debugAndroidTestRuntimeClasspath
      '.|androidx.test:core@1.5.0|dev|gradle.lockfile|-',
      '.|com.fasterxml.jackson.core:jackson-annotations@2.17.1|transitive|gradle.lockfile|-',
      '.|com.fasterxml.jackson.core:jackson-core@2.17.1|transitive|gradle.lockfile|-',
      '.|com.fasterxml.jackson.core:jackson-databind@2.17.1|direct|gradle.lockfile|2.17.+',
      // runtime and test classpaths: runtime wins
      '.|com.google.guava:guava@33.2.0-jre|direct|gradle.lockfile|$guavaVersion',
      '.|junit:junit@4.13.2|dev|gradle.lockfile|-',
      '.|org.hamcrest:hamcrest-core@1.3|dev|gradle.lockfile|-',
      // declared with testImplementation only, but on compileClasspath: transitive there
      '.|org.mockito:mockito-core@5.12.0|transitive|gradle.lockfile|-',
      '.|org.projectlombok:lombok@1.18.32|direct|gradle.lockfile|1.18.32',
      '.|org.slf4j:slf4j-api@2.0.13|transitive|gradle.lockfile|-',
      // lock without a build file: nothing is known to be direct
      'lib|org.apache.commons:commons-lang3@3.14.0|transitive|gradle.lockfile|-',
      'lib|org.junit.jupiter:junit-jupiter-api@5.10.2|dev|gradle.lockfile|-',
    ]);
    const result = parseEcosystemCase('java', 'java', 'gradle-lockfile');
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['build.gradle', 'gradle.lockfile', 'lib/gradle.lockfile']);
    // the malformed line is skipped with one record; comments and `empty=` are not entries
    expect(result.parse_errors).toEqual([{ ecosystem: 'java', file: 'gradle.lockfile', error: PARSER_MESSAGES.invalidEntry }]);
    expect(result.dependencies.find((d) => d.name === 'com.google.guava:guava')?.purl).toBe('pkg:maven/com.google.guava/guava@33.2.0-jre');
  });

  it('line rules: comments, blank lines and empty= skipped; CRLF accepted; no valid line but malformed ones -> structure error', () => {
    const lock = parseGradleLockfile('# c\r\n\r\ng:a:1.0=testRuntimeClasspath,androidTestCompileClasspath\r\nh:b:2.0=runtimeClasspath,testRuntimeClasspath\r\nempty=\r\n');
    expect(lock).toEqual({
      lines: [
        { name: 'g:a', version: '1.0', testOnly: true },
        { name: 'h:b', version: '2.0', testOnly: false },
      ],
      invalid: false,
    });
    expect(parseGradleLockfile('# only comments\nempty=\n')).toEqual({ lines: [], invalid: false });
    expect(parseGradleLockfile('g:a:1=x\ng:a=x\ng::1=x\n').invalid).toBe(true);
    expect(() => parseGradleLockfile('nonsense\n')).toThrow(PARSER_MESSAGES.structure);
  });
});

describe('REQ-011 P-40 / R-2 / AC-P40-6: pom.xml', () => {
  it('properties (nested, project.*, parent), dependencyManagement version and scope, test/optional/provided/runtime; unresolved, range and dynamic -> version null', () => {
    expect(brief(rows('pom-properties'))).toEqual([
      // property cycle
      '.|com.example.cyclic:cyclic@-|direct|pom.xml|${cycle.a}',
      '.|com.example:demo-common@1.4.0|direct|pom.xml|${project.version}',
      '.|com.fasterxml.jackson.core:jackson-databind@2.17.1|direct|pom.xml|${jackson.version}',
      '.|com.google.code.gson:gson@-|direct|pom.xml|[2.10,3.0)',
      // property defined only in the parent POM
      '.|io.micrometer:micrometer-core@-|direct|pom.xml|${micrometer.version}',
      '.|jakarta.servlet:jakarta.servlet-api@6.0.0|direct|pom.xml|6.0.0',
      // version from dependencyManagement (as written there)
      '.|org.apache.commons:commons-lang3@3.14.0|direct|pom.xml|${commons.version}',
      '.|org.junit.jupiter:junit-jupiter@5.10.2|dev|pom.xml|5.10.2',
      // scope test from dependencyManagement
      '.|org.mockito:mockito-core@5.12.0|dev|pom.xml|5.12.0',
      '.|org.postgresql:postgresql@42.7.3|direct|pom.xml|42.7.3',
      '.|org.springframework.boot:spring-boot-configuration-processor@3.3.0|optional|pom.xml|${project.parent.version}',
      // managed by the parent POM / the imported BOM: nothing written in this file
      '.|org.springframework.boot:spring-boot-starter-web@-|direct|pom.xml|-',
      '.|org.yaml:snakeyaml@-|direct|pom.xml|LATEST',
      '.|software.amazon.awssdk:s3@-|direct|pom.xml|-',
      // no own version: project.version = parent version
      'module-a|com.example:demo-common@1.4.0|direct|pom.xml|${project.version}',
      // neither own nor parent version
      'module-b|com.example:module-a@-|direct|pom.xml|${project.version}',
    ]);
    const result = parseEcosystemCase('java', 'java', 'pom-properties');
    // plugin and profile dependencies are not read
    expect(result.dependencies.some((d) => d.name.includes('plugin-only') || d.name.includes('profile-only'))).toBe(false);
    expect(result.dependencies.filter((d) => d.version === null).every((d) => !d.purl.includes('@'))).toBe(true);
    expect(result.parse_errors).toEqual([{ ecosystem: 'java', file: 'pom.xml', error: PARSER_MESSAGES.invalidEntry }]);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['module-a/pom.xml', 'module-b/pom.xml', 'pom.xml']);
  });

  it('exponential property nesting stays bounded (result over 1 024 code units is unresolved)', () => {
    const props = Array.from({ length: 40 }, (_, i) => `<p${i}>\${p${i + 1}}\${p${i + 1}}</p${i}>`).join('') + '<p40>x</p40>';
    const pom = `<project><properties>${props}</properties><dependencies><dependency><groupId>g</groupId><artifactId>a</artifactId><version>\${p0}</version></dependency></dependencies></project>`;
    const started = Date.now();
    const data = parsePom(Buffer.from(pom));
    expect(Date.now() - started).toBeLessThan(2000);
    expect(data.declarations).toEqual([{ name: 'g:a', version: null, declared: '${p0}', scope: 'direct' }]);
  });

  it('root element must be project; DOCTYPE is rejected by the XML reader', () => {
    expect(() => parsePom(Buffer.from('<settings/>'))).toThrow(PARSER_MESSAGES.structure);
    expect(() => parsePom(Buffer.from('<!DOCTYPE project><project/>'))).toThrow();
  });
});

describe('REQ-011 P-40 / R-1: build.gradle and build.gradle.kts', () => {
  it('Groovy: string, comma list, map notation, variables, dynamic/range, strict shorthand, classifier; platform/project/files/catalog/constraints skipped', () => {
    expect(brief(rows('gradle-groovy'))).toEqual([
      '.|androidx.test.espresso:espresso-core@3.5.1|dev|build.gradle|3.5.1',
      '.|com.fasterxml.jackson.core:jackson-core@-|direct|build.gradle|$jacksonVersion',
      '.|com.fasterxml.jackson.core:jackson-databind@-|direct|build.gradle|${jacksonVersion}',
      '.|com.google.guava:guava@33.2.0-jre|direct|build.gradle|33.2.0-jre',
      '.|com.squareup.leakcanary:leakcanary-android@2.14|direct|build.gradle|2.14',
      // also testImplementation: runtime scope kept
      '.|com.squareup.okhttp3:okhttp@4.12.0|direct|build.gradle|4.12.0',
      '.|commons-io:commons-io@2.16.1|direct|build.gradle|2.16.1',
      '.|io.netty:netty-all@-|direct|build.gradle|4.1.+',
      '.|joda-time:joda-time@-|direct|build.gradle|[2.10,3.0)',
      '.|org.apache.commons:commons-lang3@3.14.0|direct|build.gradle|3.14.0',
      '.|org.apache.httpcomponents:httpclient@4.5.14|direct|build.gradle|4.5.14',
      '.|org.jetbrains:annotations@24.1.0|direct|build.gradle|24.1.0!!',
      '.|org.junit.jupiter:junit-jupiter@5.10.2|dev|build.gradle|5.10.2',
      '.|org.junit.platform:junit-platform-launcher@1.10.2|dev|build.gradle|1.10.2',
      '.|org.postgresql:postgresql@42.7.3|direct|build.gradle|42.7.3',
      '.|org.projectlombok:lombok@1.18.32|direct|build.gradle|1.18.32',
      '.|org.slf4j:slf4j-api@-|direct|build.gradle|slf4jVersion',
      '.|org.springframework.boot:spring-boot-starter-actuator@-|direct|build.gradle|-',
      '.|org.springframework.boot:spring-boot-starter-web@3.3.0|direct|build.gradle|3.3.0',
      '.|org.yaml:snakeyaml@-|direct|build.gradle|latest.release',
    ]);
    const result = parseEcosystemCase('java', 'java', 'gradle-groovy');
    expect(result.dependencies.some((d) => /log4j|commented|spring-boot-dependencies|micronaut|commons-logging/.test(d.name))).toBe(false);
    // `implementation 'not-a-coordinate'`
    expect(result.parse_errors).toEqual([{ ecosystem: 'java', file: 'build.gradle', error: PARSER_MESSAGES.invalidEntry }]);
  });

  it('Kotlin DSL: templates (incl. catalog versions) -> null; named arguments; ksp/kapt; kotlin()/platform()/project()/libs aliases skipped', () => {
    expect(brief(rows('gradle-kts'))).toEqual([
      // version from the platform BOM
      '.|androidx.compose.ui:ui@-|direct|build.gradle.kts|-',
      '.|androidx.test.ext:junit@1.1.5|dev|build.gradle.kts|1.1.5',
      '.|ch.qos.logback:logback-classic@1.5.6|direct|build.gradle.kts|1.5.6',
      '.|com.google.code.gson:gson@2.11.0|direct|build.gradle.kts|2.11.0',
      '.|com.google.dagger:dagger-compiler@2.51.1|direct|build.gradle.kts|2.51.1',
      '.|com.squareup.moshi:moshi@-|direct|build.gradle.kts|1.+',
      // ksp (direct) and kspTest (dev): runtime kept
      '.|com.squareup.moshi:moshi-kotlin-codegen@1.15.1|direct|build.gradle.kts|1.15.1',
      '.|com.squareup.okhttp3:okhttp@-|direct|build.gradle.kts|${libs.versions.okhttp.get()}',
      '.|io.github.example:strict@1.2.3|direct|build.gradle.kts|1.2.3',
      '.|io.ktor:ktor-server-core@-|direct|build.gradle.kts|$ktorVersion',
      '.|io.ktor:ktor-server-netty@-|direct|build.gradle.kts|${ktorVersion}',
      '.|io.mockk:mockk@1.13.11|dev|build.gradle.kts|1.13.11',
      '.|javax.annotation:jsr250-api@1.0|direct|build.gradle.kts|1.0',
      '.|org.jetbrains.kotlinx:kotlinx-coroutines-core@1.8.1|direct|build.gradle.kts|1.8.1',
    ]);
    expect(parseEcosystemCase('java', 'java', 'gradle-kts').parse_errors).toEqual([]);
  });

  it('configuration names', () => {
    for (const name of ['implementation', 'api', 'compileOnly', 'runtimeOnly', 'compile', 'kapt', 'ksp', 'kspTest', 'kaptAndroidTest', 'testImplementation', 'androidTestImplementation', 'debugImplementation', 'testFixturesApi', 'testRuntimeOnly', 'testAnnotationProcessor']) {
      expect(isGradleConfiguration(name), name).toBe(true);
    }
    for (const name of ['classpath', 'id', 'exclude', 'Implementation', 'implementations', 'version', 'platform', 'mavenCentral']) {
      expect(isGradleConfiguration(name), name).toBe(false);
    }
  });

  it('exact version rule: plain versions only; dynamic selectors, ranges, variables are not exact', () => {
    for (const v of ['1.0', '33.2.0-jre', '1.0.0-SNAPSHOT', '2.0.0.Final', '1.0~rc1']) expect(isExactMavenVersion(v), v).toBe(true);
    for (const v of ['1.+', '+', '1.0+', 'latest.release', 'latest.integration', 'LATEST', 'RELEASE', '[1.0,2.0)', '(,1.0]', '${v}', '$v', '1.0 ', '']) {
      expect(isExactMavenVersion(v), v).toBe(false);
    }
  });

  it('lexer: comments dropped, URLs inside strings kept, Kotlin templates with nested quotes, unterminated string/comment -> structure error', () => {
    const tokens = lexGradle('// x\nimplementation("g:a:${property("v")}") /* y */ url "https://example.org//x"');
    expect(tokens.filter((t) => t.kind === 'str').map((t) => t.value)).toEqual(['g:a:${property("v")}', 'https://example.org//x']);
    expect(() => lexGradle("implementation 'g:a:1\n")).toThrow(PARSER_MESSAGES.structure);
    expect(() => lexGradle('/* open')).toThrow(PARSER_MESSAGES.structure);
    expect(() => lexGradle('"${open')).toThrow(PARSER_MESSAGES.structure);
  });

  it('linear on large hostile input', () => {
    const started = Date.now();
    expect(parseGradleScript('implementation('.repeat(100_000) + 'constraints {'.repeat(50_000)).declarations).toEqual([]);
    // deep template nesting is refused (bounded recursion), not a stack overflow
    expect(() => lexGradle('"${'.repeat(100_000))).toThrow(PARSER_MESSAGES.structure);
    expect(lexGradle('"a${"b${"c"}"}"')).toEqual([{ kind: 'str', value: 'a${"b${"c"}"}' }]);
    const many = "implementation 'g:a:1', ".repeat(50_000);
    expect(parseGradleScript(many).declarations.length).toBe(50_000);
    expect(Date.now() - started).toBeLessThan(5000);
  });
});

describe('REQ-011 AC-P40-2: source priority per folder', () => {
  it('gradle.lockfile > pom.xml > build.gradle(.kts); lock folders also read the build files for direct/transitive; both scripts read when both exist', () => {
    expect(brief(rows('priority'))).toEqual([
      'a-lock-wins|com.google.guava:failureaccess@1.0.2|transitive|gradle.lockfile|-',
      'a-lock-wins|com.google.guava:guava@33.2.0-jre|direct|gradle.lockfile|33.+',
      // declared in the sibling pom.xml
      'a-lock-wins|org.apache.commons:commons-lang3@3.14.0|direct|gradle.lockfile|3.14.0',
      'a-lock-wins|org.junit.jupiter:junit-jupiter@5.10.2|dev|gradle.lockfile|-',
      'b-pom-wins|org.slf4j:slf4j-api@2.0.13|direct|pom.xml|2.0.13',
      'c-both-scripts|io.mockk:mockk@1.13.11|dev|build.gradle.kts|1.13.11',
      'c-both-scripts|org.slf4j:slf4j-api@2.0.13|direct|build.gradle|2.0.13',
    ]);
    const result = parseEcosystemCase('java', 'java', 'priority');
    // b-pom-wins/build.gradle is not used, so it is not a scan file
    expect(result.scan_files.map((f) => f.file_path)).toEqual([
      'a-lock-wins/build.gradle',
      'a-lock-wins/gradle.lockfile',
      'a-lock-wins/pom.xml',
      'b-pom-wins/pom.xml',
      'c-both-scripts/build.gradle',
      'c-both-scripts/build.gradle.kts',
    ]);
  });
});

describe('REQ-011 AC-P40-3 / AC-P40-4: broken Java files', () => {
  it('one fixed Turkish record per file; DOCTYPE rejected; broken lock/pom falls back to the next source; other folders continue', () => {
    const result = parseEcosystemCase('java', 'java', 'broken');
    expect(result.parse_errors).toEqual([
      { ecosystem: 'java', file: 'a-bad-xml/pom.xml', error: PARSER_MESSAGES.xmlMalformed },
      { ecosystem: 'java', file: 'b-doctype/pom.xml', error: PARSER_MESSAGES.xmlDoctype },
      { ecosystem: 'java', file: 'c-bad-lock/gradle.lockfile', error: PARSER_MESSAGES.structure },
      { ecosystem: 'java', file: 'd-bad-gradle/build.gradle', error: PARSER_MESSAGES.structure },
      { ecosystem: 'java', file: 'e-not-project/pom.xml', error: PARSER_MESSAGES.structure },
      { ecosystem: 'java', file: 'f-invalid-entries/build.gradle.kts', error: PARSER_MESSAGES.invalidEntry },
      { ecosystem: 'java', file: 'g-unclosed-comment/build.gradle.kts', error: PARSER_MESSAGES.structure },
    ]);
    expect(brief(result.dependencies)).toEqual([
      'a-bad-xml|org.slf4j:slf4j-api@2.0.13|direct|build.gradle|2.0.13',
      'c-bad-lock|org.apache.commons:commons-lang3@3.14.0|direct|pom.xml|3.14.0',
      'f-invalid-entries|org.slf4j:slf4j-api@2.0.13|direct|build.gradle.kts|2.0.13',
    ]);
    expect(result.scan_files.map((f) => f.file_path)).toEqual(['a-bad-xml/build.gradle', 'c-bad-lock/pom.xml', 'f-invalid-entries/build.gradle.kts']);
    for (const e of result.parse_errors) expect(e.error).not.toMatch(/secret|oops|passwd|[\\/:]/);
  });
});
