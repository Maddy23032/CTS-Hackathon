import asyncio
from database import get_vulnerabilities_collection

async def check_vulns():
    collection = await get_vulnerabilities_collection()
    vulns = await collection.find().limit(5).to_list(length=5)
    print(f"Found {len(vulns)} vulnerabilities")

    for i, v in enumerate(vulns):
        print(f"Vuln {i+1}:")
        print(f"  Type: {v.get('vulnerability_type')}")
        print(f"  Has ai_summary: {'ai_summary' in v}")
        print(f"  Has remediation: {'remediation' in v}")
        if 'ai_summary' in v:
            print(f"  ai_summary: {v['ai_summary']}")
        if 'remediation' in v:
            print(f"  remediation: {v['remediation'][:100]}...")
        print()

if __name__ == "__main__":
    asyncio.run(check_vulns())
