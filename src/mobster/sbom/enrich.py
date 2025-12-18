from datetime import datetime
from abc import ABC, abstractmethod
from pathlib import Path
import json, os
from typing import Any, Iterable, Sequence

from packageurl import PackageURL
from dataclasses import dataclass

import mobster.sbom.merge as merge 
from mobster.sbom.merge import CDXComponent, SBOMItem, SPDXPackage

@dataclass
class SBOMElement(SBOMItem):
    data: dict[str,Any]

    def id(self) -> str:
        """No-op since this is a not an actual SBOM."""

    def name(self) -> str:
        """Get the name of the SBOM item."""
        self.data["name"]

    def version(self) -> str:
        """No-op since this is a not an actual SBOM."""

    def purl(self) -> PackageURL | None:
        if purl_str := self.data.get("purl"):
            return merge.try_parse_purl(purl_str)
        return None
    
    def unwrap(self) -> dict[str,Any]:
        return self.data 

def wrap_as_element(items: Iterable[dict[str, Any]]) -> list[SBOMElement]:
    """
    Wrap a list of dictionary elements into SBOMElement objects.
    """
    return list(map(SBOMElement, items))

def purl_without_version(purl: PackageURL): 
    '''
    Returns the inputted purl without the version.
    Allows for equality of purls regardless of version
    '''
    purl = purl._replace(version=None)
    return purl

def all_purls(sbom: Sequence[SBOMItem]):
    all_purls = {}
    for index, component in enumerate(sbom):
        all_purls[purl_without_version(component.purl())] = index
    return all_purls

def general_enrich(enrichFunc, target_sbom: Sequence[SBOMItem], incoming_sbom: Sequence[SBOMItem]):
        target_purls = all_purls(target_sbom)
        
        target_packages = [component.unwrap() for component in target_sbom]
        for element in incoming_sbom: 
            if purl_without_version(element.purl()) in target_purls:
                index = target_purls[purl_without_version(element.purl())]
                component_to_enrich = target_sbom[index]
                newPackage = enrichFunc(component_to_enrich.unwrap(), element.unwrap())
                if newPackage: 
                    target_packages[index] = newPackage 
        return target_packages


class SBOMEnricher(ABC):
    
    @abstractmethod 
    def enrich(
        self,
        target_sbom: dict[str, Any],
        incoming_sbom: dict[str, Any],
    ) -> dict[str, Any]:  # pragma: no cover
        """
        Enrich two SBOMs.
        This method should be implemented by subclasses.
        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom
        Returns:
            dict[str, Any]: The enriched SBOM
        """
        raise NotImplementedError("Enrich method logic is implemented in subclasses.")
    

class CycloneDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for CycloneDX SBOMs.
    """

    def enrich(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a CycloneDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        target_components = merge.wrap_as_cdx(target_sbom["components"])
        try:
            if merge._detect_sbom_type(incoming_sbom) == "cyclonedx":
                incoming_components = merge.wrap_as_cdx(incoming_sbom["components"])
                #doesn't account for duplicaes (assumes its a new tool)
                target_sbom["metadata"]["tools"]["components"].extend(incoming_sbom["metadata"]["tools"]["components"])
                target_sbom["components"] = general_enrich(self.mergeModelCards,target_components, incoming_components)
            else: 
                incoming_packages = merge.wrap_as_spdx(incoming_sbom["packages"])
                target_sbom["components"] = self.enrich_from_spdx(target_sbom, incoming_packages)
        except ValueError as e: 
            print(f"{e}, treating enrichment file as json")
            incoming_elements = wrap_as_element(incoming_sbom["components"])
            target_sbom["components"] = general_enrich(self.convertToModelCard,target_components, incoming_elements)
        
        return target_sbom
                
           
    def enrich_from_spdx(self, target_sbom: Sequence[CDXComponent], incoming_sbom: Sequence[SPDXPackage]) -> dict[str, Any]:
        raise NotImplementedError("TODO: implement this")


    def convertToModelCard(self, target_component: dict[str, Any], incoming_component: dict[str,Any]):
        '''
        This is intended for when the incoming component is a json file, not an sbom. 
        We can convert the incoming fields to a model card format, then pass it in the mergeModelCards func
        '''
        print("HERE!!")
        incoming_component["modelCard"] = {
            "modelParameters": {},
            "properties": incoming_component["data"]
        }

        return self.mergeModelCards(target_component, incoming_component)
    def mergeModelCards(self, target_component: dict[str,Any], incoming_component: dict[str, Any]):
        if not "modelCard" in target_component: 
            target_component["modelCard"] = incoming_component["modelCard"]
            return target_component
        
        newModelCard = target_component["modelCard"]

        #TODO: should probably also be adding on to the modelParameters?
        newModelCard["modelParameters"] = incoming_component["modelCard"]["modelParameters"]
        
        if "modelCard" in incoming_component: 
            '''
            parts of a modelCard:
            modelParameters
                - architectureFamily
                - inputs: [{format: value}]
                - modelArchitecture
                - outputs: [{format: value}]
                - task
            properties:
                - {name : value}
            '''
            newProperties = [] if not "properties" in newModelCard else newModelCard["properties"]
            targetProperties = incoming_component["modelCard"]["properties"]
            #add everything from incoming properties that isn't already in the target properties
            [p for p in newProperties if not p in targetProperties]
            newModelCard["properties"] = newProperties + [p for p in newProperties if not p in targetProperties]


        target_component["modelCard"] = newModelCard
        return target_component
        
    
class SPDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for SPDX SBOMs.
    """

    def enrich(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a SPDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        target_packages = merge.wrap_as_spdx(target_sbom.get("packages", []))
        if merge._detect_sbom_type(incoming_sbom) == "cyclonedx":
            target_sbom["creationInfo"] = self.addToTools(target_sbom["creationInfo"], incoming_sbom["metadata"]["tools"])
            target_sbom["packages"] = general_enrich(self.enrichPackage, target_packages, merge.wrap_as_cdx(incoming_sbom.get("components", [])))
            return target_sbom
        
        return self.enrich_from_same_type(target_sbom, incoming_sbom) 
    
    def enrich_from_same_type(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError("TODO: implement this")
        
    
    def addToTools(self, creationInfo: dict[str,Any], tools: dict[str,Any]):
        for component in tools["components"]:
            creationInfo["creators"].append(f"Tool: {component["name"]}")
        return creationInfo
    def enrichPackage(self, package: dict[str,Any], component: dict[str,Any]):
        
        if "modelCard" in component:
            modelCard = component["modelCard"]
            annotations = []
            
            for field in modelCard['properties']:
                fieldName, fieldValue = field['name'], field['value']

                #bomFormat doesn't go in SPDX and serialNumber gets rebuilt as the SPDX id
                #specversion doesn't matter because we're using the SPDX version of the original
                prefer_original = ['bomFormat', 'serialNumber', 'specVersion', 'external_references', 'downloadLocation', 'version']
                if fieldName in prefer_original:
                    continue

                script_path = Path(__file__).resolve()
                script_dir = script_path.parent
                
                spdxFieldName = self.getFieldName(f"{script_dir}/enrich_tools/SPDXmappings2.3.json", fieldName)
                #don't overwrite the field if its in the original SBOM, but add it in if its not
                if spdxFieldName and not (fieldName in package):
                    package[spdxFieldName] = fieldValue 
                    continue 

                
                spdxAIFieldName = self.getFieldName(f"{script_dir}/enrich_tools/SPDXmappingAI.json", fieldName)
                if spdxAIFieldName:   
                    self.makeAnnotationFromField(spdxAIFieldName, fieldValue) 
                    annotations.append(self.makeAnnotationFromField(spdxAIFieldName, fieldValue))
                    continue 

                print(f"The field {fieldName} does not correspond to any SPDX field or AI field. Skipping over field {field}")

            package["annotations"].extend(annotations)

        #TODO: should this look in something else besides modelCard? like metadata?
        return package
        
    
    def makeAnnotationFromField(self, field, value):
        annotation = {"annotationDate": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "annotationType" : "OTHER",
                      "annotator": "Tool: OWASP AIBOM Generator",
                      "comment" : f"{field} : {value}"}
        return annotation 
    
    def getFieldName(self, file_path, fieldName):
        try:
            with open(file_path, 'r') as f:
                mappings = json.load(f)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            raise e
        if fieldName in mappings:
            return  mappings[fieldName]['SPDX_Equivalent']
        return None




def _create_enricher(
    target_sbom: dict[str, Any]
) -> SBOMEnricher:
    """
    Creates a merger for the given SBOMs.
    """
    target_type = merge._detect_sbom_type(target_sbom)

    if target_type == "cyclonedx":
        return CycloneDXEnricher()

    return SPDXEnricher() 

async def enrich_sbom(
    target_sbom: Path, incoming_sbom: Path | None = None
) -> dict[str, Any]:
    """
    Merge multiple SBOMs.

    This is the main entrypoint function for merging SBOMs.
    Currently supports merging multiple Syft SBOMs with up to
    1 Hermeto SBOM.

    Args:
        syft_sbom_paths: List of paths to Syft SBOMs
        hermeto_sbom_path: Optional path to Hermeto SBOM

    Returns:
        The merged SBOM

    Raises:
        ValueError: If there are not enough SBOMs to merge (at least
        one Syft SBOM with Hermeto SBOM, or multiple Syft SBOMs)
    """

    if not target_sbom or not incoming_sbom:
        raise ValueError("A target SBOM path and an incoming SBOM is required to enrich an SBOM.")
    
    target_sbom_loaded = await merge.load_sbom_from_json(target_sbom)
    incoming_sbom_loaded = await merge.load_sbom_from_json(incoming_sbom)
    #we only need the type of the target SBOM to create the enricher
    enricher = _create_enricher(target_sbom_loaded)
    return enricher.enrich(target_sbom_loaded, incoming_sbom_loaded)