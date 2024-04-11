# Study Roadmap

与恶意软件开发不同，木马免杀需要考虑杀毒软件的检测逻辑以及各种绕过手法。恶意软件开发通常专注于实现特定功能，而木马免杀除了技术实现外，还必须考虑如何规避杀毒软件的检测机制。

在本仓库中，我们涵盖了恶意软件开发和木马免杀的技术知识。需要明确的是，并非所有代码都具备免杀效果。

## About Bypass AntiVirus

免杀技术的学习路线分为四大块：静态、动态、内存和网络。初学者可以按照这一路线逐步学习，先从静态技术入手，然后逐步深入动态、内存和网络方面的知识。在网络侧，我们提供了 C2 profile 和云函数脚本。

需要明确的是，免杀的核心在于对抗检测机制。检测通常涵盖多个层面，因此要实现完整的免杀效果，需要结合多种绕过手法。一些提供的loader仅作为基础知识点，本身并不具备免杀效果。在学习过程中，需要注意将不同的绕过手法组合起来。部分小结会提供组合成品，通过实践可以更好地理解和发现。

### 0x01 Static Analysis Evasion

#### 1.shellcode encryption and encoding

##### i. Base64

##### ii . AES

##### iii. RC4

**iV. XOR**

#### 2.call obfuscation

#### 3.Entropy

#### 4.Signature



### 0x02 Dynamic Behavioral Evasion

#### **1.Anti sandbox**

#### **2.Anti VM**

#### **3.reload ntdll**

#### **4.Syscall**

#### **5.PPID Spoffing**

#### 6.COM组件滥用



### 0x03 Memory Scanners Evasion

#### **1.睡眠混淆**

#### **2.内存加密**



### 0x04 Network traffic Evasion

#### 1.C2profile



#### 2.云函数



