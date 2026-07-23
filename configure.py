# vim: set sts=2 ts=8 sw=2 tw=99 et:
import sys
from ambuild2 import run

parser = run.BuildParser(sourcePath=sys.path[0], api='2.2')
parser.options.add_argument('--hl2sdk-root', type=str, dest='hl2sdk_root', default=None,
                            help='Root search folder for HL2SDKs')
parser.options.add_argument('--hl2sdk-manifest-path', type=str, dest='hl2sdk_manifest', default=None,
                            help='Path to hl2sdk-manifests when it is not checked out locally')
parser.options.add_argument('--mms-path', type=str, dest='mms_path', default=None,
                            help='Path to Metamod:Source')
parser.options.add_argument('--sm-path', type=str, dest='sm_path', default=None,
                            help='Path to SourceMod')
parser.options.add_argument('--enable-debug', action='store_const', const='1', dest='debug',
                            help='Enable debugging symbols')
parser.options.add_argument('--enable-optimize', action='store_const', const='1', dest='opt',
                            help='Enable optimization')
parser.options.add_argument('-s', '--sdks', default='present', dest='sdks',
                            help='SDKs to build: all, present, or a comma-delimited manifest list')
parser.options.add_argument('--targets', type=str, dest='targets', default=None,
                            help='Target architectures, separated by commas (x86,x86_64)')
parser.Configure()
