/*
 * The MIT License
 *
 * Copyright 2022 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package cryptotest.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

/**
 * utility class to find any Interface implementing classes in netx/icedtea-web
 */
public class ClassFinder {

    public static final String JAVA_CLASS_PATH_PROPERTY = "java.class.path";
    public static final String CUSTOM_CLASS_PATH_PROPERTY = "custom.class.path";
    public static final String BOOT_CLASS_PATH_PROPERTY = "sun.boot.class.path";

    static public List<Class<? extends AlgorithmTest>> findAllAlgorithmTest() {
        List<Class<? extends AlgorithmTest>> r = ClassFinder.findAllMatchingTypes(AlgorithmTest.class);
        for (Class<? extends AlgorithmTest> test : r) {
            if (test.getName().equals("cryptotest.utils.AlgorithmTest")) {
                r.remove(test);
                //only one to do
                return r;
            }
        }
        return r;
    }

    static public <T> List<Class<? extends T>> findAllMatchingTypes(Class<T> toFind) {
        List<Class<? extends T>> returnedClasses = new ArrayList<>();
        Set<Class> foundClasses = walkClassPath(toFind);
        for (Class<?> clazz : foundClasses) {
            if (!clazz.isInterface()) {
                returnedClasses.add((Class<? extends T>) clazz);
            }
        }
        return returnedClasses;
    }

    static private Set<Class> walkClassPath(Class toFind) {
        Set<Class> results = new HashSet<>();
        Set<String> classPathRoots = getClassPathRoots();
        for (String classpathEntry : classPathRoots) {
            //it would be nice to avoid base jdk jars/modules by some path name check like http://icedtea.classpath.org/hg/icedtea-web/file/bb764e3ccbc9/netx/net/sourceforge/jnlp/controlpanel/ClassFinder.java#l76
            if (true) {
                File f = new File(classpathEntry);
                //this is supposed to be jtreg test, or ismple set of classes, so scaning only direcotries
                if (!f.isDirectory()) {
                    continue;
                }
                if (!f.exists()) {
                    continue;
                }
                if (f.isDirectory()) {
                    traverse(f.getAbsolutePath(), f, toFind, results);
                } else {
                    File jar = new File(classpathEntry);
                    try {
                        JarInputStream is = new JarInputStream(new FileInputStream(jar));
                        JarEntry entry;
                        while ((entry = is.getNextJarEntry()) != null) {
                            Class c = determine(entry.getName(), toFind);
                            if (c != null) {
                                results.add(c);
                            }
                        }
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                }
            }
        }
        return results;
    }

    static private Set<String> getClassPathRoots() {
        String classapth1 = System.getProperty(CUSTOM_CLASS_PATH_PROPERTY);
        String classapth2 = System.getProperty(JAVA_CLASS_PATH_PROPERTY);
        String classapth3 = System.getProperty(BOOT_CLASS_PATH_PROPERTY);
        String classpath = "";
        if (classapth1 != null) {
            classpath = classpath + classapth1 + File.pathSeparator;
        }
        if (classapth2 != null) {
            classpath = classpath + classapth2 + File.pathSeparator;
        }
        if (classapth3 != null) {
            classpath = classpath + classapth3 + File.pathSeparator;
        }
        String[] pathElements = classpath.split(File.pathSeparator);
        Set<String> s = new HashSet<>(Arrays.asList(pathElements));
        return s;
    }

    static private Class determine(String name, Class toFind) {
        if (name.contains("$")) {
            return null;
        }
        try {
            if (name.endsWith(".class")) {
                name = name.replace(".class", "");
                name = name.replace("/", ".");
                name = name.replace("\\", ".");
                Class clazz = Class.forName(name);
                if (toFind.isAssignableFrom(clazz)) {
                    return clazz;
                }
            }
        } catch (Throwable ex) {
            //blacklisted classes
            //System.out.println(name);
        }
        return null;
    }

    static private void traverse(String root, File current, Class toFind, Set<Class> result) {
        File[] fs = current.listFiles();
        for (File f : fs) {
            if (f.isDirectory()) {
                traverse(root, f, toFind, result);
            } else {
                String ff = f.getAbsolutePath();
                String name = ff.substring(root.length());
                while (name.startsWith(File.separator)) {
                    name = name.substring(1);
                }
                Class c = determine(name, toFind);
                if (c != null) {
                    result.add(c);
                }
            }

        }
    }

}
