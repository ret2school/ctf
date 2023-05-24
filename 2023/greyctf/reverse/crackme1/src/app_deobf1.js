'use strict';

var dico = [
    "bindTransformFeedback",
    "createElement",
    "40865qozUos",
    "286guTpAq",
    "activeTexture",
    "1412856CuNLHL",
    "7iETngL",
    "linkProgram",
    "attachShader",
    "canvas",
    "TRANSFORM_FEEDBACK",
    "viewport",
    "generateMipmap",
    "#flag",
    "querySelector",
    "src",
    "a_position",
    "createProgram",
    "log",
    "push",
    "textInput",
    "texImage2D",
    "createBuffer",
    "24695GHmWxv",
    "#version 300 es\n\nin vec4 a_position;\nout vec2 v_texcoord;\n\n// all shaders have a main function\nvoid main() {\n\n  // gl_Position is a special variable a vertex shader\n  // is responsible for setting\n  gl_Position = a_position;\n  v_texcoord.x = (gl_Position.x + 1.0f) / 2.0f;\n  v_texcoord.y = -(gl_Position.y + 1.0f) / 2.0f;\n}\n",
    "startsWith",
    "compileShader",
    "RGBA",
    "#version 300 es\n\nuniform vec4 s;\n\nin float a;\nin float b;\nin float c;\nin float d;\nin float e;\n\nout float f;\n\nvoid main() {\n  f = (a * d + b + c * e) * (step(0.0f, -abs(s.z)));\n}\n",
    "thonk.png",
    "bindBufferBase",
    "TEXTURE_WRAP_S",
    "deleteProgram",
    "createShader",
    "3398536yTzYal",
    "enableVertexAttribArray",
    "TEXTURE_2D",
    "getUniformLocation",
    "LINK_STATUS",
    "NEAREST",
    "charCodeAt",
    "VERTEX_SHADER",
    "115729dJqjLi",
    "transformFeedbackVaryings",
    "fromCharCode",
    "ARRAY_BUFFER",
    "STATIC_DRAW",
    "COLOR_BUFFER_BIT",
    "bufferData",
    "getProgramParameter",
    "FRAGMENT_SHADER",
    "vertexAttribPointer",
    "textContent",
    "11392452WoAIUJ",
    "drawArrays",
    "UNSIGNED_BYTE",
    "createTexture",
    "COMPILE_STATUS",
    "bindTexture",
    "bindBuffer",
    "useProgram",
    "round",
    "resizeCanvasToDisplaySize",
    "addEventListener",
    "TEXTURE_MIN_FILTER",
    "webgl2",
    "bindVertexArray",
    "getAttribLocation",
    "FLOAT",
    "fill",
    "length",
    "7970WJoyDR",
    "clearColor",
    "24555sMhSaO",
    "774iHtBiv",
    "click",
    "height",
    "CLAMP_TO_EDGE",
    "TEXTURE_MAG_FILTER",
    "submitButton",
    "getContext",
    "getShaderParameter",
    "getElementById",
    "POINTS",
    "TRIANGLES",
    "#version 300 es\nprecision highp float;\n\nout vec4 outColor;\nvoid main() {\n  outColor = vec4(0.0f, 1.0f, 0.0f, 1.0f);\n}\n",
    "TEXTURE0",
    "createTransformFeedback",
    "uniform4fv",
    "texParameteri",
    "noentry.jpg",
    "load"
];

function dico_shift(i) {
    return dico[i - 0x171];
}

// Juste un espèce de checksum pour pas qu'on modifie des trucs (je pense)
(function() {
    while (!![]) {
        try {
            var _0x1b2964 = parseInt(dico_shift(0x19b)) / 0x1 + -parseInt(dico_shift(0x174)) / 0x2 * (parseInt(dico_shift(0x1ba)) / 0x3) + parseInt(dico_shift(0x176)) / 0x4 + -parseInt(dico_shift(0x188)) / 0x5 * (parseInt(dico_shift(0x1bb)) / 0x6) + parseInt(dico_shift(0x177)) / 0x7 * (parseInt(dico_shift(0x193)) / 0x8) + -parseInt(dico_shift(0x1a6)) / 0x9 + parseInt(dico_shift(0x1b8)) / 0xa * (parseInt(dico_shift(0x173)) / 0xb);
            if (_0x1b2964 === 781201) break; //normalement c'est vrai
            else dico['push'](dico['shift']()); //devrait faire 91
        } catch (_0x2875c0) {
            dico['push'](dico['shift']());
        }
    }
}());


const _0x386235 = '#version 300 es\n\nuniform vec4 s;\n\nin float a;\nin float b;\nin float c;\nin float d;\nin float e;\n\nout float f;\n\nvoid main() {\n  f = (a * d + b + c * e) * (step(0.0f, -abs(s.z)));\n}\n',
    _0x47330c = '#version 300 es\nprecision highp float;\n\nout vec4 outColor;\nvoid main() {\n  outColor = vec4(0.0f, 1.0f, 0.0f, 1.0f);\n}\n',
    _0x58b76b = '#version 300 es\n\nin vec4 a_position;\nout vec2 v_texcoord;\n\n// all shaders have a main function\nvoid main() {\n\n  // gl_Position is a special variable a vertex shader\n  // is responsible for setting\n  gl_Position = a_position;\n  v_texcoord.x = (gl_Position.x + 1.0f) / 2.0f;\n  v_texcoord.y = -(gl_Position.y + 1.0f) / 2.0f;\n}\n',
    _0x43c55a = '#version\x20300\x20es\x0a\x0a//\x20fragment\x20shaders\x20don\x27t\x20have\x20a\x20default\x20precision\x20so\x20we\x20need\x0a//\x20to\x20pick\x20one.\x20highp\x20is\x20a\x20good\x20default.\x20It\x20means\x20\x22high\x20precision\x22\x0aprecision\x20highp\x20float;\x0a\x0ain\x20vec2\x20v_texcoord;\x0auniform\x20sampler2D\x20u_texture;\x0a\x0aout\x20vec4\x20outColor;\x0a\x0avoid\x20main()\x20{\x0a\x20\x20outColor\x20=\x20texture(u_texture,\x20v_texcoord);\x0a}\x0a',
    _0x2dc759 = document['createElement']('canvas'),
    _0x3c93ad = _0x2dc759['getContext']('webgl2');
var _0x67ee6b = document['querySelector']('#c'),
    _0x3a9ce9 = _0x67ee6b['getContext']('webgl2');
webglUtils['resizeCanvasToDisplaySize'](_0x3a9ce9['canvas']), _0x3a9ce9['viewport'](0x0, 0x0, _0x3a9ce9['canvas']['width'], _0x3a9ce9['canvas']['height']);

function _0x48be04(_0x3da04, _0x407d15, _0x10d5e3) {
    const _0x45c783 = _0x3da04['createShader'](_0x407d15);
    _0x3da04['shaderSource'](_0x45c783, _0x10d5e3), _0x3da04['compileShader'](_0x45c783);
    if (!_0x3da04['getShaderParameter'](_0x45c783, _0x3da04['COMPILE_STATUS'])) throw new Error(_0x3da04['getShaderInfoLog'](_0x45c783));
    return _0x45c783;
}

function _0x19f621(_0x5b0944, _0x3b6d48, _0x8a8243) {
    var _0x1ab715 = _0x5b0944['createProgram']();
    _0x5b0944['attachShader'](_0x1ab715, _0x3b6d48), _0x5b0944['attachShader'](_0x1ab715, _0x8a8243), _0x5b0944['linkProgram'](_0x1ab715);
    var _0x34ae3c = _0x5b0944['getProgramParameter'](_0x1ab715, _0x5b0944['LINK_STATUS']);
    if (_0x34ae3c) return _0x1ab715;
    return console['log'](_0x5b0944['getProgramInfoLog'](_0x1ab715)), _0x5b0944['deleteProgram'](_0x1ab715), undefined;
}

function _0x206eb0(_0x2fcd6c, _0x151f49) {
    const _0x224a76 = _0x2fcd6c['createBuffer']();
    return _0x2fcd6c['bindBuffer'](_0x2fcd6c['ARRAY_BUFFER'], _0x224a76), _0x2fcd6c['bufferData'](_0x2fcd6c['ARRAY_BUFFER'], _0x151f49, _0x2fcd6c['STATIC_DRAW']), _0x224a76;
}

function _0x4d1ce5(_0x54d2ad, _0x16a27e, _0x44bb18) {
    const _0x5c5368 = _0x206eb0(_0x54d2ad, _0x16a27e);
    _0x54d2ad['enableVertexAttribArray'](_0x44bb18), _0x54d2ad['vertexAttribPointer'](_0x44bb18, 0x1, _0x54d2ad['FLOAT'], ![], 0x0, 0x0);
}
const _0x1b8e20 = _0x48be04(_0x3c93ad, _0x3c93ad['VERTEX_SHADER'], _0x386235),
    _0x534164 = _0x48be04(_0x3c93ad, _0x3c93ad['FRAGMENT_SHADER'], _0x47330c),
    _0x4ca650 = _0x3c93ad['createProgram']();
_0x3c93ad['attachShader'](_0x4ca650, _0x1b8e20), _0x3c93ad['attachShader'](_0x4ca650, _0x534164), _0x3c93ad['transformFeedbackVaryings'](_0x4ca650, ['f'], _0x3c93ad['SEPARATE_ATTRIBS']), _0x3c93ad['linkProgram'](_0x4ca650);
if (!_0x3c93ad['getProgramParameter'](_0x4ca650, _0x3c93ad['LINK_STATUS'])) throw new Error(_0x3c93ad['getProgramParameter'](_0x4ca650));
const _0xf2d081 = _0x3c93ad['getAttribLocation'](_0x4ca650, 'a'),
    _0xf1f47a = _0x3c93ad['getAttribLocation'](_0x4ca650, 'b'),
    _0x47d8c9 = _0x3c93ad['getAttribLocation'](_0x4ca650, 'c'),
    _0x449c60 = _0x3c93ad['getAttribLocation'](_0x4ca650, 'd'),
    _0xd06f29 = _0x3c93ad['getAttribLocation'](_0x4ca650, 'e'),
    _0x597fc3 = _0x3c93ad['getUniformLocation'](_0x4ca650, 's'),
    _0x37ea82 = _0x3c93ad['createVertexArray']();
_0x3c93ad['bindVertexArray'](_0x37ea82);
var _0x1a6c13 = _0x48be04(_0x3a9ce9, _0x3a9ce9['VERTEX_SHADER'], _0x58b76b),
    _0x249b0e = _0x48be04(_0x3a9ce9, _0x3a9ce9['FRAGMENT_SHADER'], _0x43c55a),
    _0x142487 = _0x19f621(_0x3a9ce9, _0x1a6c13, _0x249b0e),
    _0x29e7ae = _0x3a9ce9['getAttribLocation'](_0x142487, 'a_position'),
    _0x56ee60 = _0x3a9ce9['createBuffer']();
_0x3a9ce9['bindBuffer'](_0x3a9ce9['ARRAY_BUFFER'], _0x56ee60);
var _0x3e48db = [0x1, -0x1, -0x1, -0x1, -0x1, 0x1, -0x1, 0x1, 0x1, -0x1, 0x1, 0x1];
_0x3a9ce9['bufferData'](_0x3a9ce9['ARRAY_BUFFER'], new Float32Array(_0x3e48db), _0x3a9ce9['STATIC_DRAW']);
var _0x5745db = _0x3a9ce9['createVertexArray']();
_0x3a9ce9['bindVertexArray'](_0x5745db), _0x3a9ce9['enableVertexAttribArray'](_0x29e7ae);
var _0x288b88 = 0x2,
    _0xe0eefa = _0x3a9ce9['FLOAT'],
    _0x22a8e6 = ![],
    _0x38a39a = 0x0,
    _0x2cdd83 = 0x0;
_0x3a9ce9['vertexAttribPointer'](_0x29e7ae, _0x288b88, _0xe0eefa, _0x22a8e6, _0x38a39a, _0x2cdd83);
var _0x56d2d3 = _0x3a9ce9['createTexture']();
_0x3a9ce9['bindTexture'](_0x3a9ce9['TEXTURE_2D'], _0x56d2d3), _0x3a9ce9['texImage2D'](_0x3a9ce9['TEXTURE_2D'], 0x0, _0x3a9ce9['RGBA'], 0x1, 0x1, 0x0, _0x3a9ce9['RGBA'], _0x3a9ce9['UNSIGNED_BYTE'], new Uint8Array([0x0, 0xb4, 0xff, 0xff]));
var _0x20da9b = new Image();
_0x20da9b['src'] = 'thonk.png', _0x20da9b['addEventListener']('load', function() {
    _0x3a9ce9['bindTexture'](_0x3a9ce9['TEXTURE_2D'], _0x56d2d3), _0x3a9ce9['texImage2D'](_0x3a9ce9['TEXTURE_2D'], 0x0, _0x3a9ce9['RGBA'], _0x3a9ce9['RGBA'], _0x3a9ce9['UNSIGNED_BYTE'], _0x20da9b), _0x3a9ce9['generateMipmap'](_0x3a9ce9['TEXTURE_2D']), _0x3a9ce9['useProgram'](_0x142487);
    var _0xdb67ac = _0x3a9ce9['TRIANGLES'],
        _0x2506c5 = 0x0,
        _0x21db03 = 0x6;
    _0x3a9ce9['drawArrays'](_0xdb67ac, _0x2506c5, _0x21db03);
});
var _0x5998de = [_0x3a9ce9['createTexture'](), _0x3a9ce9['createTexture']()],
    _0x3d5c0d = _0x3a9ce9['createTexture'](),
    _0x378267 = new Image();
_0x378267['src'] = 'noentry.jpg', _0x378267['addEventListener']('load', function() {
    _0x3a9ce9['bindTexture'](_0x3a9ce9['TEXTURE_2D'], _0x5998de[0x0]), _0x3a9ce9['texImage2D'](_0x3a9ce9['TEXTURE_2D'], 0x0, _0x3a9ce9['RGBA'], _0x3a9ce9['RGBA'], _0x3a9ce9['UNSIGNED_BYTE'], _0x378267), _0x3a9ce9['generateMipmap'](_0x3a9ce9['TEXTURE_2D']);
});

var _0x577a5f = new Image();
_0x577a5f['src'] = 'good.png', _0x577a5f['addEventListener']('load', function() {
    _0x3a9ce9['bindTexture'](_0x3a9ce9['TEXTURE_2D'], _0x5998de[0x1]), _0x3a9ce9['texImage2D'](_0x3a9ce9['TEXTURE_2D'], 0x0, _0x3a9ce9['RGBA'], _0x3a9ce9['RGBA'], _0x3a9ce9['UNSIGNED_BYTE'], _0x577a5f), _0x3a9ce9['generateMipmap'](_0x3a9ce9['TEXTURE_2D']);
});
const _0x70bcf7 = [
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x0, 0x0, 0x0, 0x0],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1],
        [0x1, 0x0, 0x1, 0x1]
    ],
    _0x427775 = [
        [0xe5, 0x0, 0x0, 0x0],
        [0xf4, 0x0, 0x0, 0x0],
        [0xf8, 0x0, 0x0, 0x0],
        [0x3d, 0x0, 0x0, 0x0],
        [0x26, 0x0, 0x0, 0x0],
        [0x5, 0x0, 0x0, 0x0],
        [0xf1, 0x0, 0x0, 0x0],
        [0x29, 0x0, 0x0, 0x0],
        [0x43, 0x0, 0x0, 0x0],
        [0x6, 0x0, 0x0, 0x0],
        [0x5d, 0x0, 0x0, 0x0],
        [0x54, 0x0, 0x0, 0x0],
        [0xc2, 0x0, 0x0, 0x0],
        [0xf2, 0x0, 0x0, 0x0],
        [0x6, 0x0, 0x0, 0x0],
        [0x71, 0x0, 0x0, 0x0],
        [0xb5, 0x0, 0x0, 0x0],
        [0xd5, 0x0, 0x0, 0x0],
        [0x46, 0x0, 0x0, 0x0],
        [0x21, 0x0, 0x0, 0x0],
        [0xcc, 0x0, 0x0, 0x0],
        [0x2, 0x0, 0x0, 0x0],
        [0x80, 0x0, 0x0, 0x0],
        [0x95, 0x0, 0x0, 0x0],
        [0x42, 0x0, -0x45, 0x3],
        [0xda, 0x0, 0x0, 0x0],
        [0x53, 0x0, 0x0, 0x0],
        [0x61, 0x0, 0x0, 0x0],
        [-0x10, 0x0, 0x0, 0x0],
        [0x22, 0x0, 0x0, 0x0],
        [0xdd, 0x0, 0x0, 0x0],
        [0x50, 0x0, 0x0, 0x0],
        [0x90, 0x0, 0x0, 0x0],
        [0x28, 0x0, 0x0, 0x0],
        [0x66, 0x0, 0x0, 0x0],
        [0x6b, 0x0, 0x0, 0x0],
        [0xcc, 0x0, 0x0, 0x0],
        [0xe, 0x0, 0x0, 0x0],
        [0x78, 0x0, 0x0, 0x0],
        [-0x25, 0x0, 0x0, 0x0],
        [-0x22, 0x0, 0x0, 0x0],
        [0x59, 0x0, 0x0, 0x0],
        [0xad, 0x0, -0x63, -0x6],
        [-0x11, 0x0, 0x0, 0x0],
        [0x69, 0x0, -0x52, 0x2],
        [0xa0, 0x0, 0x0, 0x0],
        [0x1c, 0x0, 0x0, 0x0],
        [0xac, 0x0, 0x0, 0x0],
        [0xb7, 0x0, 0x0, 0x0],
        [0x83, 0x0, -0x63, 0x7],
        [0x7d, 0x0, -0x49, -0x8],
        [0x2f, 0x0, 0x0, 0x0],
        [0x2a, 0x0, 0x0, 0x0],
        [0x24, 0x0, 0x0, 0x0],
        [0xc7, 0x0, 0x0, 0x0],
        [0x88, 0x0, 0x0, 0x0],
        [0x80, 0x0, 0x0, 0x0],
        [0x61, 0x0, 0x0, 0x0],
        [0x88, 0x0, 0x0, 0x0],
        [-0x1d, 0x0, 0x0, 0x0],
        [0x88, 0x0, 0x0, 0x0],
        [0xab, 0x0, 0x0, 0x0],
        [0x1e, 0x0, 0x0, 0x0],
        [0x2, 0x0, 0x0, 0x0],
        [0x28, 0x0, 0x0, 0x0],
        [0xa1, 0x0, 0x0, 0x0],
        [0xbc, 0x0, 0x0, 0x0],
        [0xc, 0x0, 0x0, 0x0],
        [0x5e, 0x0, 0x0, 0x0],
        [-0x37, 0x0, 0x0, 0x0],
        [-0x29, 0x0, 0x0, 0x0],
        [0x97, 0x0, -0x45, -0x7],
        [0x1d, 0x0, 0x0, 0x0],
        [0x14, 0x0, 0x0, 0x0],
        [0x6d, 0x0, 0x0, 0x0],
        [0x81, 0x0, 0x0, 0x0],
        [-0x9, 0x0, 0x0, 0x0],
        [0x47, 0x0, 0x0, 0x0],
        [-0x14, 0x0, 0x0, 0x0],
        [0x92, 0x0, 0x0, 0x0],
        [-0xe, 0x0, 0x0, 0x0],
        [-0x18, 0x0, 0x0, 0x0],
        [0x17, 0x0, 0x0, 0x0],
        [0x32, 0x0, 0x0, 0x0],
        [0x4c, 0x0, 0x0, 0x0],
        [0xa3, 0x0, 0x0, 0x0],
        [0x37, 0x0, 0x0, 0x0],
        [0x94, 0x0, 0x0, 0x0],
        [0xc, 0x0, 0x0, 0x0],
        [-0x47, 0x0, 0x0, 0x0],
        [0x1e, 0x0, -0x68, 0x7],
        [0x78, 0x0, 0x0, 0x0],
        [0x57, 0x0, 0x0, 0x0],
        [0x54, 0x0, 0x0, 0x0],
        [0x2, 0x0, 0x0, 0x0],
        [0x6a, 0x0, 0x0, 0x0],
        [0x8e, 0x0, 0x0, 0x0],
        [-0x3f, 0x0, 0x0, 0x0],
        [0x65, 0x0, 0x0, 0x0],
        [-0x13, 0x0, -0x69, 0x4],
        [-0x3e, 0x0, 0x0, 0x0],
        [0x8a, 0x0, 0x0, 0x0],
        [-0x28, 0x0, 0x0, 0x0],
        [0x4f, 0x0, 0x0, 0x0],
        [-0x3d, 0x0, 0x0, 0x0],
        [-0x37, 0x0, 0x0, 0x0],
        [0x10, 0x0, 0x0, 0x0],
        [-0x5a, 0x0, 0x0, 0x0],
        [0xb, 0x0, 0x0, 0x0],
        [-0x52, 0x0, 0x0, 0x0],
        [-0x2, 0x0, 0x0, 0x0],
        [0x14, 0x0, 0x0, 0x0],
        [0x23, 0x0, 0x0, 0x0],
        [-0x61, 0x0, 0x0, 0x0],
        [0xf, 0x0, 0x0, 0x0],
        [0x5e, 0x0, 0x0, 0x0],
        [-0x2d, 0x0, 0x0, 0x0],
        [-0x3, 0x0, 0x0, 0x0],
        [0x3f, 0x0, -0x50, -0x2],
        [-0x42, 0x0, 0x0, 0x0],
        [0x46, 0x0, 0x0, 0x0],
        [-0x4d, 0x0, 0x0, 0x0],
        [-0x49, 0x0, 0x0, 0x0],
        [-0x37, 0x0, 0x0, 0x0],
        [-0x77, 0x0, 0x0, 0x0],
        [0x27, 0x0, 0x0, 0x0],
        [0x5e, 0x0, 0x0, 0x0],
        [0x3c, 0x0, 0x0, 0x0],
        [-0xa, 0x0, 0x0, 0x0],
        [-0x10, 0x0, 0x0, 0x0],
        [-0xd, 0x0, 0x0, 0x0],
        [0x18, 0x0, 0x0, 0x0],
        [0x56, 0x0, 0x0, 0x0],
        [0x28, 0x0, 0x0, 0x0],
        [0x16, 0x0, 0x0, 0x0],
        [-0x5e, 0x0, 0x0, 0x0],
        [-0x81, 0x0, 0x0, 0x0],
        [-0x3b, 0x0, 0x0, 0x0],
        [0x6c, 0x0, 0x0, 0x0],
        [-0x18, 0x0, -0x65, -0x1],
        [-0x76, 0x0, 0x0, 0x0],
        [-0x14, 0x0, 0x0, 0x0],
        [0x4f, 0x0, 0x0, 0x0],
        [0x9, 0x0, 0x0, 0x0],
        [-0x9, 0x0, 0x0, 0x0],
        [0x61, 0x0, 0x0, 0x0],
        [-0x6e, 0x0, 0x0, 0x0],
        [-0x18, 0x0, 0x0, 0x0],
        [-0x3d, 0x0, 0x0, 0x0],
        [0x2e, 0x0, 0x0, 0x0],
        [0x26, 0x0, 0x0, 0x0],
        [-0x7f, 0x0, 0x0, 0x0],
        [0xb, 0x0, 0x0, 0x0],
        [0x4b, 0x0, 0x0, 0x0],
        [-0x75, 0x0, 0x0, 0x0],
        [-0x98, 0x0, 0x0, 0x0],
        [-0x7d, 0x0, 0x0, 0x0],
        [-0x4c, 0x0, 0x0, 0x0],
        [0xa, 0x0, 0x0, 0x0],
        [0x39, 0x0, 0x0, 0x0],
        [-0x1c, 0x0, 0x0, 0x0],
        [-0x65, 0x0, 0x0, 0x0],
        [0x2e, 0x0, 0x0, 0x0],
        [0x1d, 0x0, 0x0, 0x0],
        [-0x69, 0x0, 0x0, 0x0],
        [-0x50, 0x0, 0x0, 0x0],
        [0x39, 0x0, 0x0, 0x0],
        [-0x1b, 0x0, 0x0, 0x0],
        [0x45, 0x0, 0x0, 0x0],
        [-0x12, 0x0, 0x0, 0x0],
        [0x40, 0x0, 0x0, 0x0],
        [-0xc, 0x0, 0x0, 0x0],
        [0x48, 0x0, 0x0, 0x0],
        [-0x1e, 0x0, 0x0, 0x0],
        [-0x28, 0x0, 0x0, 0x0],
        [-0x63, 0x0, 0x0, 0x0],
        [-0x8d, 0x0, 0x0, 0x0],
        [-0x1f, 0x0, 0x0, 0x0],
        [-0x57, 0x0, 0x0, 0x0],
        [0x1f, 0x0, 0x0, 0x0],
        [-0x23, 0x0, 0x0, 0x0],
        [0x34, 0x0, 0x0, 0x0],
        [0x10, 0x0, 0x0, 0x0],
        [-0x4c, 0x0, 0x0, 0x0],
        [-0x7b, 0x0, 0x0, 0x0],
        [-0x12, 0x0, -0x6b, -0x1],
        [-0x68, 0x0, 0x0, 0x0],
        [-0x51, 0x0, 0x0, 0x0],
        [-0x33, 0x0, 0x0, 0x0],
        [-0x14, 0x0, 0x0, 0x0],
        [-0x25, 0x0, 0x0, 0x0],
        [0xc, 0x0, 0x0, 0x0],
        [-0x4c, 0x0, -0x44, 0xa],
        [0x15, 0x0, 0x0, 0x0],
        [0x3a, 0x0, 0x0, 0x0],
        [-0x70, 0x0, 0x0, 0x0],
        [-0x61, 0x0, 0x0, 0x0],
        [-0x96, 0x0, 0x0, 0x0],
        [-0x8f, 0x0, 0x0, 0x0],
        [-0x9f, 0x0, 0x0, 0x0],
        [-0x80, 0x0, 0x0, 0x0],
        [-0x23, 0x0, 0x0, 0x0],
        [-0xae, 0x0, 0x0, 0x0],
        [0x26, 0x0, 0x0, 0x0],
        [0xd, 0x0, 0x0, 0x0],
        [-0xc5, 0x0, 0x0, 0x0],
        [-0x3e, 0x0, 0x0, 0x0],
        [0xcf, 0x1, 0x0, 0x0],
        [-0x7a, 0x0, 0x0, 0x0],
        [-0x2c, 0x0, 0x0, 0x0],
        [-0x31, 0x0, 0x0, 0x0],
        [-0xb, 0x0, 0x0, 0x0],
        [-0xc1, 0x0, 0x0, 0x0],
        [-0x4a, 0x0, 0x0, 0x0],
        [0xd, 0x0, 0x0, 0x0],
        [-0xb7, 0x0, 0x0, 0x0],
        [-0x2a, 0x0, 0x0, 0x0],
        [-0xa, 0x0, 0x0, 0x0],
        [-0x8d, 0x0, 0x0, 0x0],
        [-0xd0, 0x0, 0x0, 0x0],
        [-0xbb, 0x0, 0x0, 0x0],
        [-0x6f, 0x0, 0x0, 0x0],
        [0xe, 0x0, 0x0, 0x0],
        [-0x7e, 0x0, 0x0, 0x0],
        [-0x36, 0x0, 0x0, 0x0],
        [-0x62, 0x0, 0x0, 0x0],
        [-0x8e, 0x0, 0x0, 0x0],
        [-0xf, 0x0, 0x0, 0x0],
        [-0x2a, 0x0, 0x0, 0x0],
        [-0x48, 0x0, 0x0, 0x0],
        [-0x25, 0x0, 0x0, 0x0],
        [-0x6a, 0x0, 0x0, 0x0],
        [-0xdb, 0x0, 0x0, 0x0],
        [-0x14, 0x0, 0x0, 0x0],
        [-0xe9, 0x0, 0x0, 0x0],
        [-0xd6, 0x0, 0x0, 0x0],
        [-0x86, 0x0, 0x0, 0x0],
        [-0xbf, 0x0, 0x0, 0x0],
        [-0x64, 0x0, 0x0, 0x0],
        [-0x44, 0x0, 0x0, 0x0],
        [-0xc9, 0x0, 0x0, 0x0],
        [-0xab, 0x0, 0x0, 0x0],
        [-0xe9, 0x0, 0x0, 0x0],
        [-0x29, 0x0, 0x0, 0x0],
        [-0xdb, 0x0, 0x0, 0x0],
        [-0xc8, 0x0, 0x0, 0x0],
        [-0xbe, 0x0, 0x0, 0x0],
        [-0x79, 0x0, 0x0, 0x0],
        [-0x3f, 0x0, 0x0, 0x0],
        [-0x3c, 0x0, -0x6e, -0x8],
        [-0x8a, 0x0, 0x0, 0x0],
        [-0xb6, 0x0, 0x0, 0x0],
        [-0xf8, 0x0, 0x0, 0x0],
        [-0x4, 0x0, 0x0, 0x0],
        [-0xc8, 0x0, 0x0, 0x0],
        [-0x4d, 0x0, 0x0, 0x0]
    ],
    _0x5505b3 = [
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x1, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0],
        [0x0, 0x0, 0x0, 0x0]
    ];

function _0x1d1d26(_0xb0b479) {
    var _0x350e0d = [0x0, 0x0, 0x0, 0x0],
        _0x234507 = [0x0, 0x0, 0x0, 0x0],
        _0x39ea71 = [0x0, 0x0, 0x0, 0x0],
        _0x1e0e64 = [0x0, 0x0, 0x0, 0x0],
        _0x2e88e3 = [0x41, 0x41, 0x41, 0x41];
    for (var _0x42bb4f = 0x0; _0x42bb4f < 0x104; ++_0x42bb4f) {
        const _0x3d0205 = _0x4d1ce5(_0x3c93ad, new Float32Array(_0x350e0d), _0xf2d081),
            _0x1bbc48 = _0x4d1ce5(_0x3c93ad, new Float32Array(_0x234507), _0xf1f47a),
            _0x12ff68 = _0x4d1ce5(_0x3c93ad, new Float32Array(_0x39ea71), _0x47d8c9),
            _0x358438 = _0x4d1ce5(_0x3c93ad, new Float32Array(_0x1e0e64), _0x449c60),
            _0x31fd87 = _0x4d1ce5(_0x3c93ad, new Float32Array(_0x2e88e3), _0xd06f29),
            _0x5efde3 = _0x3c93ad['createTransformFeedback']();
        _0x3c93ad['bindTransformFeedback'](_0x3c93ad['TRANSFORM_FEEDBACK'], _0x5efde3);
        const _0x237696 = _0x206eb0(_0x3c93ad, _0x350e0d['length'] * 0x4);
        _0x3c93ad['bindBufferBase'](_0x3c93ad['TRANSFORM_FEEDBACK_BUFFER'], 0x0, _0x237696), _0x3c93ad['bindTransformFeedback'](_0x3c93ad['TRANSFORM_FEEDBACK'], null), _0x3c93ad['bindBuffer'](_0x3c93ad['ARRAY_BUFFER'], null), _0x3c93ad['useProgram'](_0x4ca650), _0x3c93ad['bindVertexArray'](_0x37ea82), _0x3c93ad['bindTransformFeedback'](_0x3c93ad['TRANSFORM_FEEDBACK'], _0x5efde3), _0x3c93ad['beginTransformFeedback'](_0x3c93ad['POINTS']), _0x3c93ad['drawArrays'](_0x3c93ad['POINTS'], 0x0, _0x350e0d['length']), _0x3c93ad['endTransformFeedback'](), _0x3c93ad['bindTransformFeedback'](_0x3c93ad['TRANSFORM_FEEDBACK'], null);
        const _0x5a9b29 = new Float32Array(_0x350e0d['length']);
        _0x3c93ad['bindBuffer'](_0x3c93ad['ARRAY_BUFFER'], _0x237696), _0x3c93ad['getBufferSubData'](_0x3c93ad['ARRAY_BUFFER'], 0x0, _0x5a9b29);
        for (var _0x531283 = 0x0; _0x531283 < 0x4; ++_0x531283) {
            _0x1e0e64[_0x531283] = Math['round'](_0x5a9b29[_0x531283]) % 0x100, _0x2e88e3 = _0x2e88e3['fill'](_0xb0b479['charCodeAt'](_0x1e0e64[_0x531283])), _0x350e0d[_0x531283] = _0x70bcf7[_0x1e0e64[0x0]][_0x531283], _0x234507[_0x531283] = _0x427775[_0x1e0e64[0x0]][_0x531283], _0x39ea71[_0x531283] = _0x5505b3[_0x1e0e64[0x0]][_0x531283];
        }
        _0x3c93ad['uniform4fv'](_0x597fc3, _0x1e0e64), _0x3a9ce9['clearColor'](0x0, 0x0, 0x0, 0x0), _0x3a9ce9['clear'](_0x3c93ad['COLOR_BUFFER_BIT']), _0x3a9ce9['useProgram'](_0x142487), _0x3a9ce9['activeTexture'](_0x3a9ce9['TEXTURE0'] + 0x1), _0x3a9ce9['bindTexture'](_0x3a9ce9['TEXTURE_2D'], _0x3d5c0d), _0x3a9ce9['texParameteri'](_0x3a9ce9['TEXTURE_2D'], _0x3a9ce9['TEXTURE_WRAP_S'], _0x3a9ce9['CLAMP_TO_EDGE']), _0x3a9ce9['texParameteri'](_0x3a9ce9['TEXTURE_2D'], _0x3a9ce9['TEXTURE_WRAP_T'], _0x3a9ce9['CLAMP_TO_EDGE']), _0x3a9ce9['texParameteri'](_0x3a9ce9['TEXTURE_2D'], _0x3a9ce9['TEXTURE_MIN_FILTER'], _0x3a9ce9['NEAREST']), _0x3a9ce9['texParameteri'](_0x3a9ce9['TEXTURE_2D'], _0x3a9ce9['TEXTURE_MAG_FILTER'], _0x3a9ce9['NEAREST']), _0x3a9ce9['activeTexture'](_0x3a9ce9['TEXTURE0']), _0x3a9ce9['bindTexture'](_0x3a9ce9['TEXTURE_2D'], _0x5998de[_0x1e0e64[0x1]]), _0x3a9ce9['bindVertexArray'](_0x5745db), _0x3a9ce9['drawArrays'](_0x3a9ce9['TRIANGLES'], 0x0, 0x6);
    }
}

window['addEventListener']('load', () => {
    const _0x1bd4fc = document['getElementById']('submitButton');
    _0x1bd4fc['addEventListener']('click', _0x2d148f);
});

function _0x2d148f() {
    const _0x264178 = document['getElementById']('textInput');
    var _0x3be76d = _0x264178['value'];
    while (_0x3be76d['length'] < 0x400) _0x3be76d = _0x3be76d + _0x3be76d;
    _0x3be76d = _0x3be76d['substring'](0x0, 0x400), _0x1d1d26(_0x3be76d);
    var _0x5c36a9 = [0xc3, 0xb8, 0xb3, 0x42, 0xb6, 0xc2, 0x1c, 0xa4, 0xce, 0x45, 0x6, 0x3b, 0x1f, 0x1c, 0x66, 0xb1, 0x6c, 0x9a, 0x36, 0xe5, 0x14, 0xbf, 0x18, 0x6e],
        _0x35223f = _0x656fa5(_0x3be76d, 0x18),
        _0x258cbb = '';
    for (var _0x2e4a9c = 0x0; _0x2e4a9c < 0x18; ++_0x2e4a9c) {
        _0x258cbb += String['fromCharCode'](_0x5c36a9[_0x2e4a9c] ^ _0x35223f[_0x2e4a9c]);
    }
    if (_0x258cbb['startsWith']('grey{')) document['querySelector']('#flag')['textContent'] = _0x258cbb;
}

function _0x656fa5(_0x51d5a4, _0x14e107) {
    var _0x1c6239 = [],
        _0x51a6b8 = 0x0,
        _0xc583ec, _0x11ff50 = [];
    for (var _0x5c4c24 = 0x0; _0x5c4c24 < 0x100; _0x5c4c24++) {
        _0x1c6239[_0x5c4c24] = _0x5c4c24;
    }
    for (_0x5c4c24 = 0x0; _0x5c4c24 < 0x100; _0x5c4c24++) {
        _0x51a6b8 = (_0x51a6b8 + _0x1c6239[_0x5c4c24] + _0x51d5a4['charCodeAt'](_0x5c4c24 % _0x51d5a4['length'])) % 0x100, _0xc583ec = _0x1c6239[_0x5c4c24], _0x1c6239[_0x5c4c24] = _0x1c6239[_0x51a6b8], _0x1c6239[_0x51a6b8] = _0xc583ec;
    }
    _0x5c4c24 = 0x0, _0x51a6b8 = 0x0;
    for (var _0x11ada2 = 0x0; _0x11ada2 < _0x14e107; _0x11ada2++) {
        _0x5c4c24 = (_0x5c4c24 + 0x1) % 0x100, _0x51a6b8 = (_0x51a6b8 + _0x1c6239[_0x5c4c24]) % 0x100, _0xc583ec = _0x1c6239[_0x5c4c24], _0x1c6239[_0x5c4c24] = _0x1c6239[_0x51a6b8], _0x1c6239[_0x51a6b8] = _0xc583ec, _0x11ff50['push'](_0x1c6239[(_0x1c6239[_0x5c4c24] + _0x1c6239[_0x51a6b8]) % 0x100]);
    }
    return _0x11ff50;
}
