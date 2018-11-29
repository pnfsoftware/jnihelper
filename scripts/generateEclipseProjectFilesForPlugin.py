import os
import sys

tplProject = '''<?xml version="1.0" encoding="UTF-8"?>
<projectDescription>
	<name>%s</name>
	<comment></comment>
	<projects>
	</projects>
	<buildSpec>
		<buildCommand>
			<name>org.eclipse.jdt.core.javabuilder</name>
			<arguments>
			</arguments>
		</buildCommand>
	</buildSpec>
	<natures>
		<nature>org.eclipse.jdt.core.javanature</nature>
	</natures>
</projectDescription>
'''

tplClasspath = '''<?xml version="1.0" encoding="UTF-8"?>
<classpath>
	<classpathentry kind="src" path="src"/>
	<classpathentry kind="con" path="org.eclipse.jdt.launching.JRE_CONTAINER"/>
	<classpathentry kind="lib" path="%s"/>
	<classpathentry kind="output" path="bin"/>
</classpath>
'''

if __name__ == '__main__':
  if len(sys.argv) < 2:
    print('Please provide the project name as input')
    sys.exit()
  prjname = sys.argv[1]

  if 'JEB_HOME' not in os.environ:
    print('Please set an environment variable JEB_HOME pointing to your JEB folder')
    sys.exit(-1)
  jebhome = os.environ['JEB_HOME']
  jebcorepath = os.path.join(jebhome, 'bin/app/jeb.jar')
  if not os.path.isfile(jebcorepath):
    print('Based on your value of JEB_HOME, jeb.jar was expected at this location, but it was not found: %s' % jebcorepath)
    sys.exit(-1)

  with open('.project', 'w') as f:
    f.write(tplProject % prjname)
  with open('.classpath', 'w') as f:
    f.write(tplClasspath % jebcorepath)
