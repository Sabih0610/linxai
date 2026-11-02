"""Existing VPS endpoint shape, shared without importing optional SSH libraries."""
from dataclasses import dataclass
from typing import Optional,List


@dataclass
class VPSServer:
    name:str
    host:str
    port:int
    username:str
    key_path:str
    description:str=''
    tags:Optional[List[str]]=None
