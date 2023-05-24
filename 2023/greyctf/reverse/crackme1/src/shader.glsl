#version 300 es

uniform vec4 s;

in float a;
in float b;
in float c;
in float d;
in float e;

out float f;

void main() {
  // ca fait 0 si s.z est <> 0, a * d blabla... sinon
  f = (a * d + b + c * e) * (step(0.0f, -abs(s.z)));
}
